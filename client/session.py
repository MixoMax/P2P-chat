"""
session.py — manages per-peer connections.

Each peer connection goes through these states:
  PUNCHING → HANDSHAKE → READY → (DEAD)

PUNCHING:    NAT hole punching (identical to original client.py logic)
HANDSHAKE:   Exchange ephemeral X25519 keys for forward-secret encryption
READY:       Encrypted chat / media messages flow freely

The SessionManager holds all active sessions, routes inbound packets,
and exposes send_chat() / send_media() to the UI layer.
"""

import json, logging, socket, threading, time
from enum import Enum, auto
from typing import Callable, Optional
import config
from crypto import Identity, Session, RelayIdentity, frame, unframe
from transport import Transport

log = logging.getLogger("session")

class PeerState(Enum):
    PUNCHING  = auto()
    HANDSHAKE = auto()
    READY     = auto()
    DEAD      = auto()

class PeerSession:
    def __init__(self, name: str, pub_addr: tuple, priv_addr: tuple,
                 ed25519_pub: bytes, my_identity: Identity):
        self.name        = name
        self.pub_addr    = pub_addr
        self.priv_addr   = priv_addr
        self.ed25519_pub = ed25519_pub  # their signing key
        self.state       = PeerState.PUNCHING
        self.addr: Optional[tuple] = None  # confirmed reachable address
        self._session    = Session()       # ephemeral DH
        self._my_id      = my_identity
        self.connected_at: Optional[float] = None
        self.last_msg_at: Optional[float]  = None

    @property
    def eph_pub_bytes(self) -> bytes:
        return self._session.public_key_bytes

    def complete_dh(self, peer_eph_pub: bytes):
        self._session.complete_dh(peer_eph_pub)
        self.state = PeerState.READY
        self.connected_at = time.time()

    def encrypt(self, payload: dict) -> bytes:
        return frame(self._my_id, self._session, payload)

    def decrypt(self, data: bytes) -> dict | None:
        return unframe(self.ed25519_pub, self._session, data)


class SessionManager:
    def __init__(self,
                 sock: socket.socket,
                 my_name: str,
                 my_identity: Identity,
                 transport: Transport,
                 on_chat: Callable,    # on_chat(peer_name, text, timestamp)
                 on_media: Callable,   # on_media(peer_name, mime, name, data_bytes)
                 on_state: Callable):  # on_state(peer_name, PeerState)
        self._sock    = sock
        self._name    = my_name
        self._id      = my_identity
        self._tx      = transport
        self._on_chat  = on_chat
        self._on_media = on_media
        self._on_state = on_state

        self._sessions: dict[str, PeerSession] = {}
        self._addr_map: dict[tuple, str]        = {}  # addr → peer name
        self._lock = threading.Lock()

        self._punch_count    = config.get("punch_count")
        self._punch_interval = config.get("punch_interval")

        # Register inbound handlers
        transport.on_control("punch",     self._handle_punch)
        transport.on_control("hs_offer",  self._handle_hs_offer)
        transport.on_control("hs_accept", self._handle_hs_accept)
        transport.on_control("chat",      self._handle_chat)

    # ── Public API ────────────────────────────────────────────────────────────

    def connect(self, peer_info: dict, my_pub_addr: list) -> PeerSession:
        """
        Start punching and handshake with a peer asynchronously.
        Returns the PeerSession immediately (state=PUNCHING).
        """
        name     = peer_info["name"]
        pub      = tuple(peer_info["pub"])
        priv     = tuple(peer_info["priv"])
        ed_pub   = peer_info["ed25519"]

        with self._lock:
            if name in self._sessions:
                sess = self._sessions[name]
                if sess.state != PeerState.DEAD:
                    return sess
                # If DEAD, we will restart the connection process
                sess.state = PeerState.PUNCHING
                sess._session = Session() # reset DH
            else:
                sess = PeerSession(name, pub, priv, ed_pub, self._id)
                self._sessions[name] = sess

            if list(pub)[0] == my_pub_addr[0]:
                sess.addr = priv
            else:
                sess.addr = pub
            self._addr_map[sess.addr] = name

        threading.Thread(
            target=self._punch_and_handshake,
            args=(sess,),
            daemon=True,
            name=f"punch-{name}"
        ).start()

        return sess

    def send_chat(self, peer_name: str, text: str) -> bool:
        with self._lock:
            sess = self._sessions.get(peer_name)
        if not sess or sess.state != PeerState.READY:
            return False
        payload = sess.encrypt({"type": "chat", "text": text, "ts": time.time()})
        self._sock.sendto(payload, sess.addr)
        if sess:
            sess.last_msg_at = time.time()
        return True

    def send_media(self, peer_name: str, data: bytes, mime: str, filename: str) -> bool:
        with self._lock:
            sess = self._sessions.get(peer_name)
        if not sess or sess.state != PeerState.READY:
            return False
        meta = {"type": "media", "mime": mime, "name": filename}
        threading.Thread(
            target=self._tx.send_large,
            args=(sess.addr, data, meta),
            daemon=True,
        ).start()
        return True

    def get_session(self, peer_name: str) -> PeerSession | None:
        with self._lock:
            return self._sessions.get(peer_name)

    def all_sessions(self) -> dict[str, PeerSession]:
        with self._lock:
            return dict(self._sessions)

    def mark_dead(self, addr: tuple):
        with self._lock:
            name = self._addr_map.get(addr)
            if name and name in self._sessions:
                self._sessions[name].state = PeerState.DEAD
                self._on_state(name, PeerState.DEAD)

    # ── Punch + Handshake ────────────────────────────────────────────────────

    def _punch_and_handshake(self, sess: PeerSession):
        log.info("Punching %s @ %s", sess.name, sess.addr)
        punch_pkt = json.dumps({"type": "punch", "from": self._name}).encode()
        
        for _ in range(self._punch_count):
            if sess.state == PeerState.READY:
                break
            self._sock.sendto(punch_pkt, sess.addr)
            time.sleep(self._punch_interval)
            
        if sess.state != PeerState.READY:
            # wait a bit for late incoming punches to be processed by Transport -> _handle_punch
            time.sleep(1.0)
            
        log.info("Finished punching phase, sending hs_offer to %s @ %s", sess.name, sess.addr)
        self._send_hs_offer(sess)

    def _send_hs_offer(self, sess: PeerSession):
        if sess.state == PeerState.READY:
            pkt = json.dumps({
                "type":    "hs_accept",
                "from":    self._name,
                "eph_pub": sess.eph_pub_bytes.hex(),
            }).encode()
        else:
            sess.state = PeerState.HANDSHAKE
            pkt = json.dumps({
                "type":   "hs_offer",
                "from":   self._name,
                "eph_pub": sess.eph_pub_bytes.hex(),
            }).encode()
            
        for _ in range(5):
            self._sock.sendto(pkt, sess.addr)
            time.sleep(0.2)

    # ── Inbound handlers ──────────────────────────────────────────────────────

    def _handle_punch(self, addr: tuple, msg: dict):
        peer_name = msg.get("from", "")
        with self._lock:
            if peer_name in self._sessions:
                sess = self._sessions[peer_name]
                if sess.addr != addr:
                    old  = sess.addr
                    sess.addr = addr
                    self._addr_map.pop(old, None)
                    self._addr_map[addr] = peer_name
                    log.info("Observed real peer address from punch for %s: %s -> %s", peer_name, old, addr)
        # Echo punch back
        self._sock.sendto(json.dumps({"type": "punch", "from": self._name}).encode(), addr)

    def _handle_hs_offer(self, addr: tuple, msg: dict):
        peer_name = msg.get("from", "")
        with self._lock:
            sess = self._sessions.get(peer_name)
        if not sess:
            return
        peer_eph = bytes.fromhex(msg["eph_pub"])
        if sess.state != PeerState.READY:
            sess.complete_dh(peer_eph)
            self._on_state(peer_name, PeerState.READY)
            self._tx.add_known_peer(addr)
            
        # Send our own offer/accept back
        pkt = json.dumps({
            "type":    "hs_accept",
            "from":    self._name,
            "eph_pub": sess.eph_pub_bytes.hex(),
        }).encode()
        self._sock.sendto(pkt, addr)
        log.info("Handshake complete with %s (offer)", peer_name)

    def _handle_hs_accept(self, addr: tuple, msg: dict):
        peer_name = msg.get("from", "")
        with self._lock:
            sess = self._sessions.get(peer_name)
        if not sess or sess.state == PeerState.READY:
            return
        peer_eph = bytes.fromhex(msg["eph_pub"])
        sess.complete_dh(peer_eph)
        self._on_state(peer_name, PeerState.READY)
        self._tx.add_known_peer(addr)
        log.info("Handshake complete with %s (accept)", peer_name)

    def _handle_chat(self, addr: tuple, msg: dict):
        with self._lock:
            peer_name = self._addr_map.get(addr)
            sess      = self._sessions.get(peer_name) if peer_name else None
        if not sess or sess.state != PeerState.READY:
            return
        # msg here is the raw JSON (transport passes plaintext JSON for control packets)
        # For encrypted chat we need the raw bytes — but transport already decoded it.
        # Solution: the sender sends raw encrypted bytes for chat, not JSON.
        # This handler is only reached for unencrypted punch/handshake packets.
        # Encrypted chat arrives as non-JSON binary and is routed via on_message callback.
        text = msg.get("text", "")
        ts   = msg.get("ts", time.time())
        if text:
            sess.last_msg_at = ts
            self._on_chat(peer_name, text, ts)

    def handle_raw(self, addr: tuple, data: bytes):
        """Called by main for raw (potentially encrypted) inbound datagrams."""
        with self._lock:
            peer_name = self._addr_map.get(addr)
            sess      = self._sessions.get(peer_name) if peer_name else None
        if not sess or sess.state != PeerState.READY:
            return
        msg = sess.decrypt(data)
        if not msg:
            return
        t = msg.get("type", "")
        if t == "chat":
            sess.last_msg_at = msg.get("ts", time.time())
            self._on_chat(peer_name, msg["text"], sess.last_msg_at)
        elif t == "media":
            payload = msg.get("_payload_bytes", b"")
            self._on_media(peer_name, msg.get("mime",""), msg.get("name",""), payload)