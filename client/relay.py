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
from collections import defaultdict
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
        
        self._delivered_ids = set()
        self._pending_fetches = defaultdict(set)
        self._pending_deletes = defaultdict(list)
        
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

    def send_manifest(self, peer_info: dict):
        """Server announced peer is online. Send them a manifest of their messages."""
        peer_name = peer_info.get("name", "")
        peer_pub  = peer_info.get("pub")
        if not peer_name or not peer_pub:
            return
        pending = self._store.pending_for(peer_name)
        if not pending:
            return
        
        ids = [m["id"] for m in pending]
        log.info("relay: sending manifest with %d ids to %s", len(ids), peer_name)
        try:
            self._send(peer_pub, {"type": "relay_manifest", "name": self._name, "ids": ids})
        except Exception as e:
            log.debug("relay: manifest to %s failed: %s", peer_name, e)

    def handle_manifest(self, addr: tuple, msg: dict):
        """Received a manifest of waiting messages from a relay peer."""
        ids = msg.get("ids", [])
        if not ids:
            return

        needed_ids = []
        with self._lock:
            for mid in ids:
                if mid not in self._delivered_ids:
                    needed_ids.append(mid)
                    self._delivered_ids.add(mid)

            if needed_ids:
                log.info("relay: fetching %d needed messages from %s", len(needed_ids), addr)
                self._pending_deletes[addr] = ids
                self._pending_fetches[addr] = set(needed_ids)
                try:
                    self._send(addr, {"type": "relay_fetch_msg", "ids": needed_ids})
                except Exception:
                    pass
            else:
                log.info("relay: already have all messages in manifest from %s, telling them to delete", addr)
                try:
                    self._send(addr, {"type": "relay_delete", "ids": ids})
                except Exception:
                    pass

    def handle_fetch_msg(self, addr: tuple, msg: dict):
        """A peer wants to fetch specific messages we manifested."""
        ids = msg.get("ids", [])
        for mid in ids:
            m = self._store.get(mid)
            if m:
                deliver_pkt = {
                    "type":    "relay_deliver",
                    "id":      m["id"],
                    "sender":  m["sender"],
                    "payload": m["payload"].hex() if isinstance(m["payload"], bytes) else m["payload"].hex(),
                }
                try:
                    self._send(addr, deliver_pkt)
                except Exception as e:
                    log.debug("relay: deliver %s to %s failed: %s", mid, addr, e)

    def handle_delete(self, addr: tuple, msg: dict):
        """Peer told us they got the messages, we can delete them."""
        ids = msg.get("ids", [])
        log.info("relay: deleting %d messages for %s", len(ids), addr)
        for mid in ids:
            self._store.mark_delivered(mid)

    def handle_deliver(self, addr: tuple, msg: dict):
        """A relay node is delivering a stored message to us."""
        sender  = msg.get("sender", "")
        msg_id  = msg_id = msg.get("id", "")
        try:
            payload   = bytes.fromhex(msg.get("payload", ""))
            plaintext = self._rid.open(payload)
            self._on_deliver(sender, plaintext, msg_id)
        except Exception as e:
            log.debug("relay: failed to open delivered message: %s", e)

        with self._lock:
            if addr in self._pending_fetches:
                self._pending_fetches[addr].discard(msg_id)
                # Once we got all requested messages, mass delete the original manifest
                if not self._pending_fetches[addr]:
                    delete_ids = self._pending_deletes.pop(addr, [])
                    if delete_ids:
                        try:
                            self._send(addr, {"type": "relay_delete", "ids": delete_ids})
                        except Exception:
                            pass

    def handle_have(self, addr: tuple, msg: dict):
        """Peer told us which relay messages they hold — update availability."""
        ids = msg.get("ids", [])
        for mid in ids:
            self._store.increment_availability(mid)

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