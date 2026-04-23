"""
rendezvous.py — client-side rendezvous protocol.

Handles:
  • Registration (name, private addr, Ed25519 pubkey, relay X25519 pubkey)
  • Peer lookup + NAT punch coordination
  • Fetching/caching peer public keys for message verification
"""

import json, socket, threading, time, logging
from typing import Optional

import config

log = logging.getLogger("rendezvous")

TIMEOUT = 5.0

class RendezvousClient:
    def __init__(self, sock: socket.socket, my_name: str,
                 ed25519_pub: bytes, relay_x25519_pub: bytes):
        self._sock       = sock
        self._name       = my_name
        self._server     = (config.get("rendezvous_host"), config.get("rendezvous_port"))
        self._ed_pub     = ed25519_pub        # 32 bytes
        self._rx_pub     = relay_x25519_pub   # 32 bytes

        self.my_pub_addr: Optional[list] = None

        # name → {"ed25519": bytes, "relay_x25519": bytes, "pub": [ip,port], "priv": [ip,port]}
        self._peer_cache: dict[str, dict] = {}
        self._cache_lock = threading.Lock()

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, priv_addr: list) -> list:
        """
        Register with the rendezvous server.
        Returns our public [ip, port] as seen by the server.
        Blocks until acknowledged (with timeout).
        """
        payload = {
            "type":       "register",
            "name":       self._name,
            "priv":       priv_addr,
            "ed25519":    self._ed_pub.hex(),
            "relay_x25519": self._rx_pub.hex(),
        }
        deadline = time.time() + TIMEOUT
        while time.time() < deadline:
            self._sock.sendto(json.dumps(payload).encode(), self._server)
            self._sock.settimeout(1.0)
            try:
                data, addr = self._sock.recvfrom(2048)
                if addr == self._server:
                    msg = json.loads(data)
                    if msg.get("type") == "registered":
                        self.my_pub_addr = msg["your_pub"]
                        log.info("Registered as %s; public addr %s", self._name, self.my_pub_addr)
                        return self.my_pub_addr
            except socket.timeout:
                continue
        raise TimeoutError("Rendezvous registration timed out")

    # ── Peer lookup ───────────────────────────────────────────────────────────

    def request_peer(self, target: str) -> dict:
        """
        Ask the server to introduce us to `target`.
        Returns peer info dict: {"pub":[ip,port], "priv":[ip,port],
                                  "ed25519": bytes, "relay_x25519": bytes}
        Blocks until the server sends a "peer" packet back (with timeout).
        """
        payload = {
            "type":   "connect",
            "name":   self._name,
            "target": target,
        }
        deadline = time.time() + TIMEOUT * 2
        while time.time() < deadline:
            self._sock.sendto(json.dumps(payload).encode(), self._server)
            self._sock.settimeout(1.5)
            try:
                data, addr = self._sock.recvfrom(2048)
                if addr == self._server:
                    msg = json.loads(data)
                    if msg.get("type") == "peer" and msg.get("name") == target:
                        info = {
                            "pub":          tuple(msg["pub"]),
                            "priv":         tuple(msg["priv"]),
                            "ed25519":      bytes.fromhex(msg["ed25519"]),
                            "relay_x25519": bytes.fromhex(msg["relay_x25519"]),
                        }
                        with self._cache_lock:
                            self._peer_cache[target] = info
                        log.info("Got peer info for %s: %s", target, info["pub"])
                        return info
                    if msg.get("type") == "error":
                        raise RuntimeError(f"Rendezvous error: {msg.get('msg')}")
            except socket.timeout:
                continue
        raise TimeoutError(f"Peer lookup for {target} timed out")

    def get_all_peers(self) -> list[dict]:
        """
        Ask the rendezvous server for the list of ALL currently registered peers.
        Returns list of {"name": str, "pub": tuple, "ed25519": bytes, "relay_x25519": bytes}
        """
        self._sock.sendto(json.dumps({"type": "list"}).encode(), self._server)
        self._sock.settimeout(3.0)
        try:
            data, addr = self._sock.recvfrom(65535)
            if addr == self._server:
                msg = json.loads(data)
                if msg.get("type") == "peer_list":
                    result = []
                    for p in msg.get("peers", []):
                        result.append({
                            "name":         p["name"],
                            "pub":          tuple(p["pub"]),
                            "priv":         tuple(p["priv"]),
                            "ed25519":      bytes.fromhex(p["ed25519"]),
                            "relay_x25519": bytes.fromhex(p["relay_x25519"]),
                        })
                    return result
        except socket.timeout:
            pass
        return []

    def get_cached_peer(self, name: str) -> dict | None:
        with self._cache_lock:
            return self._peer_cache.get(name)

    def cache_peer(self, name: str, info: dict):
        with self._cache_lock:
            self._peer_cache[name] = info

    @property
    def server_addr(self) -> tuple:
        return self._server