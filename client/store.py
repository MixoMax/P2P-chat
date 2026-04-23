"""
store.py — SQLite-backed store-and-forward message cache.

Schema
------
  relay_messages:
    id            TEXT PRIMARY KEY    (UUID4)
    recipient     TEXT                (peer name)
    sender        TEXT
    created_at    REAL                (unix timestamp)
    expires_at    REAL
    hops_left     INTEGER             (remaining gossip hops)
    size_bytes    INTEGER
    payload       BLOB                (encrypted, opaque to us)
    delivered     INTEGER DEFAULT 0   (1 once we've sent it onward)
    availability  INTEGER DEFAULT 1   (incremented when we hear other peers have it)

Eviction policy
---------------
  When the cache is full and a new message arrives, we evict the message
  with the highest availability count that we know is also held by other
  peers (availability > 1), favouring messages that are likely to survive
  even without us.  If no such message exists we decline to store the new
  message (capacity protected).
"""

import sqlite3, time, logging, pathlib, threading
from typing import Iterator

import config

log = logging.getLogger("store")

_DDL = """
CREATE TABLE IF NOT EXISTS relay_messages (
    id           TEXT    PRIMARY KEY,
    recipient    TEXT    NOT NULL,
    sender       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    expires_at   REAL    NOT NULL,
    hops_left    INTEGER NOT NULL,
    size_bytes   INTEGER NOT NULL,
    payload      BLOB    NOT NULL,
    delivered    INTEGER NOT NULL DEFAULT 0,
    availability INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_recipient  ON relay_messages(recipient);
CREATE INDEX IF NOT EXISTS idx_expires_at ON relay_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_delivered  ON relay_messages(delivered);
"""

class MessageStore:
    def __init__(self, db_path: str = "~/.p2p-chat/relay.db"):
        p = pathlib.Path(db_path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        self._db   = sqlite3.connect(str(p), check_same_thread=False)
        self._lock = threading.Lock()
        self._limit_bytes = int(config.get("relay_cache_limit_mb") * 1024 * 1024)
        with self._lock:
            self._db.executescript(_DDL)
            self._db.commit()
        self._expire_old()

    # ── Write ─────────────────────────────────────────────────────────────────

    def store(self, msg_id: str, recipient: str, sender: str,
              payload: bytes, hops_left: int | None = None) -> bool:
        """
        Attempt to cache a relay message.
        Returns True if stored, False if rejected (duplicate or no space).
        """
        if hops_left is None:
            hops_left = config.get("relay_ttl_hops")
        if hops_left <= 0:
            return False
        ttl       = config.get("relay_ttl_seconds")
        now       = time.time()
        expires   = now + ttl
        size      = len(payload)

        with self._lock:
            # Duplicate check
            row = self._db.execute(
                "SELECT id FROM relay_messages WHERE id=?", (msg_id,)
            ).fetchone()
            if row:
                return False

            # Capacity check + eviction
            if not self._make_room(size):
                log.debug("store: no room for %s (%d B) — rejecting", msg_id, size)
                return False

            self._db.execute(
                """INSERT INTO relay_messages
                   (id, recipient, sender, created_at, expires_at,
                    hops_left, size_bytes, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (msg_id, recipient, sender, now, expires,
                 hops_left, size, payload),
            )
            self._db.commit()
            log.debug("store: cached %s for %s (%d B)", msg_id, recipient, size)
            return True

    def increment_availability(self, msg_id: str, delta: int = 1):
        """Called when we learn another peer also holds this message."""
        with self._lock:
            self._db.execute(
                "UPDATE relay_messages SET availability=availability+? WHERE id=?",
                (delta, msg_id),
            )
            self._db.commit()

    def mark_delivered(self, msg_id: str):
        with self._lock:
            self._db.execute(
                "UPDATE relay_messages SET delivered=1 WHERE id=?", (msg_id,)
            )
            self._db.commit()

    # ── Read ──────────────────────────────────────────────────────────────────

    def pending_for(self, recipient: str) -> list[dict]:
        """Return all undelivered messages for recipient."""
        now = time.time()
        with self._lock:
            rows = self._db.execute(
                """SELECT id, sender, payload, hops_left
                   FROM relay_messages
                   WHERE recipient=? AND delivered=0 AND expires_at>?""",
                (recipient, now),
            ).fetchall()
        return [{"id": r[0], "sender": r[1], "payload": r[2], "hops_left": r[3]}
                for r in rows]

    def all_relay_ids(self) -> list[str]:
        """Return IDs of all non-expired messages (for availability gossip)."""
        now = time.time()
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM relay_messages WHERE expires_at>?", (now,)
            ).fetchall()
        return [r[0] for r in rows]

    def get(self, msg_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT id, recipient, sender, payload, hops_left FROM relay_messages WHERE id=?",
                (msg_id,),
            ).fetchone()
        if not row:
            return None
        return {"id": row[0], "recipient": row[1], "sender": row[2],
                "payload": row[3], "hops_left": row[4]}

    def current_size_bytes(self) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(SUM(size_bytes),0) FROM relay_messages"
            ).fetchone()
        return row[0]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _make_room(self, needed: int) -> bool:
        """
        Evict messages until there's room for `needed` bytes.
        Eviction target: highest-availability messages first (they're
        safest to drop because other peers have them too).
        Returns False if we can't free enough space even after eviction.
        """
        current = self._db.execute(
            "SELECT COALESCE(SUM(size_bytes),0) FROM relay_messages"
        ).fetchone()[0]

        while current + needed > self._limit_bytes:
            # Find best eviction candidate: availability > 1, biggest size
            row = self._db.execute(
                """SELECT id, size_bytes FROM relay_messages
                   WHERE availability > 1
                   ORDER BY availability DESC, size_bytes DESC
                   LIMIT 1"""
            ).fetchone()
            if not row:
                # Nothing safe to evict — check if we can evict anything at all
                row = self._db.execute(
                    """SELECT id, size_bytes FROM relay_messages
                       ORDER BY expires_at ASC LIMIT 1"""
                ).fetchone()
                if not row:
                    return current + needed <= self._limit_bytes
            msg_id, size = row
            self._db.execute("DELETE FROM relay_messages WHERE id=?", (msg_id,))
            self._db.commit()
            current -= size
            log.debug("store: evicted %s to make room", msg_id)

        return True

    def _expire_old(self):
        now = time.time()
        with self._lock:
            deleted = self._db.execute(
                "DELETE FROM relay_messages WHERE expires_at<?", (now,)
            ).rowcount
            self._db.commit()
        if deleted:
            log.debug("store: expired %d old messages", deleted)