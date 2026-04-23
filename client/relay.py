"""
relay.py — store-and-forward gossip relay.

Protocol
--------
Sending a relay message (sender → all known peers):

  1. Encrypt the message to the recipient's long-term relay X25519 key
     (so relay nodes cannot read it).
  2. Wrap in a relay envelope:
       {"type": "relay",
        "id":        "<uuid4>",
        "recipient": "<name>",
        "sender":    "<name>",
        "hops_left": <int>,
        "payload":   "<hex>"}
  3. Send to EVERY peer currently known to us.
  4. Each receiving peer stores it locally and immediately re-gossips
     to all THEIR known peers (hops_left decremented).
  5. Periodically re-gossip stored messages to newly connected peers.

Delivery:
  When a peer comes online they announce themselves.
  Any node holding messages for them sends a "relay_deliver" packet.
  The recipient decrypts with their relay X25519 private key.

Availability gossip:
  Periodically broadcast "relay_have" with the list of IDs we hold.
  Recipients update availability counters so eviction is informed.
"""

import json, logging, threading, time, uuid
from typing import Callable

import config
from store import MessageStore
from crypto import RelayIdentity

log = logging.getLogger("relay")

class RelayManager:
    def __init__(self,
                 my_name: str,
                 relay_identity: RelayIdentity,
                 store: MessageStore,
                 send_fn: Callable,      # send_fn(addr, dict) — sends a JSON control packet
                 get_all_peers_fn: Callable,  # returns list of {"name","pub","relay_x25519",...}
                 on_deliver: Callable):  # on_deliver(sender, plaintext_bytes, msg_id)
        self._name        = my_name
        self._rid         = relay_identity
        self._store       = store
        self._send        = send_fn
        self._get_peers   = get_all_peers_fn
        self._on_deliver  = on_deliver
        self._rb_interval = config.get("relay_rebroadcast_interval")
        self._lock        = threading.Lock()

        threading.Thread(target=self._rebroadcast_loop, daemon=True, name="relay-rb").start()

    # ── Outbound: send a message to a potentially-offline peer ───────────────

    def send(self, recipient: str, recipient_x25519_pub: bytes, plaintext: bytes) -> str:
        """
        Encrypt plaintext for recipient and gossip to all known peers.
        Returns the message ID.
        """
        msg_id  = str(uuid.uuid4())
        hops    = config.get("relay_ttl_hops")
        payload = self._rid.seal(recipient_x25519_pub, plaintext)

        envelope = {
            "type":      "relay",
            "id":        msg_id,
            "recipient": recipient,
            "sender":    self._name,
            "hops_left": hops,
            "payload":   payload.hex(),
        }

        peers = self._get_peers()
        log.info("relay: gossiping %s to %d peers", msg_id, len(peers))
        for p in peers:
            if p["name"] != self._name:
                try:
                    self._send(p["pub"], envelope)
                except Exception as e:
                    log.debug("relay send to %s failed: %s", p["name"], e)

        # Also store locally so we can re-gossip to peers that connect later
        self._store.store(msg_id, recipient, self._name, payload, hops)
        return msg_id

    # ── Inbound: handle a received relay envelope ─────────────────────────────

    def handle_envelope(self, addr: tuple, env: dict):
        msg_id    = env.get("id", "")
        recipient = env.get("recipient", "")
        sender    = env.get("sender", "")
        hops_left = int(env.get("hops_left", 0))
        try:
            payload = bytes.fromhex(env.get("payload", ""))
        except ValueError:
            return

        if not msg_id or not recipient or not payload:
            return

        # Is it for us?
        if recipient == self._name:
            try:
                plaintext = self._rid.open(payload)
                self._on_deliver(sender, plaintext, msg_id)
            except Exception as e:
                log.debug("relay: failed to decrypt message %s: %s", msg_id, e)
            return

        # Store and re-gossip with decremented hop count
        stored = self._store.store(msg_id, recipient, sender, payload, hops_left - 1)
        if stored:
            log.debug("relay: stored %s for %s (%d hops left)", msg_id, recipient, hops_left - 1)
            if hops_left - 1 > 0:
                self._regossip_one(msg_id, recipient, sender, hops_left - 1, payload)

    def handle_fetch(self, addr: tuple, msg: dict):
        """Peer came online and is asking for pending messages."""
        peer_name = msg.get("name", "")
        if not peer_name:
            return
        pending = self._store.pending_for(peer_name)
        log.info("relay: delivering %d pending messages to %s", len(pending), peer_name)
        for m in pending:
            deliver_pkt = {
                "type":    "relay_deliver",
                "id":      m["id"],
                "sender":  m["sender"],
                "payload": m["payload"].hex() if isinstance(m["payload"], bytes) else m["payload"].hex(),
            }
            try:
                # payload from store is already bytes
                p = m["payload"]
                if isinstance(p, bytes):
                    deliver_pkt["payload"] = p.hex()
                self._send(addr, deliver_pkt)
                self._store.mark_delivered(m["id"])
            except Exception as e:
                log.debug("relay: deliver to %s failed: %s", peer_name, e)

    def handle_deliver(self, addr: tuple, msg: dict):
        """A relay node is delivering a stored message to us."""
        sender  = msg.get("sender", "")
        msg_id  = msg.get("id", "")
        try:
            payload   = bytes.fromhex(msg.get("payload", ""))
            plaintext = self._rid.open(payload)
            self._on_deliver(sender, plaintext, msg_id)
        except Exception as e:
            log.debug("relay: failed to open delivered message: %s", e)

    def handle_have(self, addr: tuple, msg: dict):
        """Peer told us which relay messages they hold — update availability."""
        ids = msg.get("ids", [])
        for mid in ids:
            self._store.increment_availability(mid)

    def announce_online(self, known_peer_addrs: list[tuple]):
        """Call when we come online to ask all known peers for pending messages."""
        fetch_pkt = {"type": "relay_fetch", "name": self._name}
        for addr in known_peer_addrs:
            try:
                self._send(addr, fetch_pkt)
            except Exception:
                pass

    # ── Internal ──────────────────────────────────────────────────────────────

    def _regossip_one(self, msg_id, recipient, sender, hops_left, payload):
        envelope = {
            "type":      "relay",
            "id":        msg_id,
            "recipient": recipient,
            "sender":    sender,
            "hops_left": hops_left,
            "payload":   payload.hex() if isinstance(payload, bytes) else payload,
        }
        peers = self._get_peers()
        for p in peers:
            if p["name"] not in (self._name, sender):
                try:
                    self._send(p["pub"], envelope)
                except Exception:
                    pass

    def _rebroadcast_loop(self):
        """Periodically re-gossip stored messages and broadcast availability."""
        while True:
            time.sleep(self._rb_interval)
            try:
                self._do_rebroadcast()
            except Exception as e:
                log.debug("relay: rebroadcast error: %s", e)

    def _do_rebroadcast(self):
        peers = self._get_peers()
        if not peers:
            return

        # Broadcast what we have (availability gossip)
        ids = self._store.all_relay_ids()
        if ids:
            have_pkt = {"type": "relay_have", "ids": ids}
            for p in peers:
                if p["name"] != self._name:
                    try:
                        self._send(p["pub"], have_pkt)
                    except Exception:
                        pass

        # Re-gossip all stored messages to all peers
        # (catches peers that weren't online during original flood)
        for mid in ids:
            m = self._store.get(mid)
            if not m or m["hops_left"] <= 0:
                continue
            envelope = {
                "type":      "relay",
                "id":        m["id"],
                "recipient": m["recipient"],
                "sender":    m["sender"],
                "hops_left": m["hops_left"],
                "payload":   m["payload"].hex() if isinstance(m["payload"], bytes) else m["payload"].hex(),
            }
            for p in peers:
                if p["name"] not in (self._name, m["sender"]):
                    try:
                        self._send(p["pub"], envelope)
                    except Exception:
                        pass