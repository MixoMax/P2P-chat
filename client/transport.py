"""
transport.py — reliable-ish UDP on top of raw sockets.

Responsibilities
----------------
  • Send large payloads (media) as numbered UDP fragments with a
    sliding-window retransmit loop.  Pure UDP — no TCP involved.
  • Reassemble inbound fragments; deliver complete payloads to callers.
  • Keepalive: send ping every N seconds, track last_seen per peer,
    fire a callback when a peer goes silent.
  • Route incoming datagrams to the right handler by packet type.

Thread model
------------
  One background thread calls _recv_loop() forever.
  It dispatches into per-type queues / callbacks so callers block
  only on their own queue.get().
"""

import json, os, socket, struct, threading, time, uuid, logging
from collections import defaultdict
from typing import Callable

import config

log = logging.getLogger("transport")

# ── Fragment header ───────────────────────────────────────────────────────────
# [4B: magic][16B: transfer_id UUID][4B: seq][4B: total][2B: flags][payload...]
# flags bit 0: is_ack

_HDR = struct.Struct(">4s16sIIH")
HDR_SIZE  = _HDR.size          # 26 bytes -> 30 bytes
FLAG_ACK  = 0x0001
FLAG_META = 0x0002             # first fragment carries JSON metadata

class Transport:
    def __init__(self, sock: socket.socket, on_message: Callable, on_peer_dead: Callable):
        """
        on_message(addr, msg_dict)   — called for every complete reassembled message
                                       AND for small control packets
        on_peer_dead(addr)           — called when keepalive times out
        """
        self._sock        = sock
        self._on_message  = on_message
        self._on_peer_dead = on_peer_dead

        self._chunk_size  = config.get("udp_chunk_size")
        self._window      = config.get("udp_window_size")
        self._ack_timeout = config.get("udp_ack_timeout")
        self._max_retries = config.get("udp_max_retries")

        # Inbound reassembly: transfer_id → {seq: bytes}
        self._in_flight: dict[bytes, dict] = defaultdict(dict)
        self._in_totals: dict[bytes, int]  = {}

        # Outbound ACK mailboxes: transfer_id → {seq: Event}
        self._ack_boxes: dict[str, dict[int, threading.Event]] = defaultdict(dict)

        # Keepalive tracking
        self._last_seen: dict[tuple, float] = {}
        self._known_peers: set[tuple]        = set()
        self._ka_interval  = config.get("keepalive_interval")
        self._ka_dead_after = config.get("keepalive_dead_after")

        # Inbound control-packet queue (non-fragment datagrams)
        self._control_handlers: dict[str, list[Callable]] = defaultdict(list)

        self._lock    = threading.Lock()
        self._running = True

        threading.Thread(target=self._recv_loop,      daemon=True, name="transport-rx").start()
        threading.Thread(target=self._keepalive_loop, daemon=True, name="transport-ka").start()

    # ── Public API ────────────────────────────────────────────────────────────

    def send_dict(self, addr: tuple, msg: dict):
        """Send a small control message as a single JSON datagram (no fragmentation)."""
        self._sock.sendto(json.dumps(msg).encode(), addr)

    def send_large(self, addr: tuple, payload: bytes, meta: dict | None = None):
        """
        Send an arbitrary-length payload via fragmented UDP with sliding-window ACKs.
        meta is JSON-serialisable metadata delivered to the receiver alongside the
        reassembled payload (e.g. {"type":"media","mime":"image/jpeg","name":"foo.jpg"}).
        Blocks until all fragments are ACKed or raises RuntimeError on failure.
        """
        tid  = uuid.uuid4().bytes          # 16-byte transfer ID
        tid_str = tid.hex()
        size = len(payload)
        cs   = self._chunk_size
        segs = [payload[i:i+cs] for i in range(0, size, cs)]
        if not segs:
            segs = [b""]
        total = len(segs)

        # Initialise ACK events
        with self._lock:
            for seq in range(total):
                ev = threading.Event()
                self._ack_boxes[tid_str][seq] = ev

        def send_fragment(seq: int):
            chunk = segs[seq]
            flags = FLAG_META if seq == 0 else 0
            hdr   = _HDR.pack(b"FRAG", tid, seq, total, flags)
            if seq == 0 and meta:
                meta_bytes = json.dumps(meta).encode()
                meta_len   = struct.pack(">H", len(meta_bytes))
                body       = hdr + meta_len + meta_bytes + chunk
            else:
                body = hdr + chunk
            self._sock.sendto(body, addr)

        # Sliding-window loop
        base    = 0
        pending = set()

        while base < total:
            # Fill window
            while len(pending) < self._window and (base + len(pending)) < total:
                seq = base + len(pending)
                send_fragment(seq)
                pending.add(seq)

            # Wait for the oldest ACK
            oldest = min(pending)
            ev     = self._ack_boxes[tid_str][oldest]
            for attempt in range(self._max_retries):
                if ev.wait(timeout=self._ack_timeout):
                    break
                send_fragment(oldest)    # retransmit
            else:
                raise RuntimeError(f"Transfer {tid_str} failed: no ACK for fragment {oldest}")

            # Slide window forward over all consecutive ACKed seqs
            while base in self._ack_boxes[tid_str] and self._ack_boxes[tid_str][base].is_set():
                pending.discard(base)
                base += 1

        # Clean up
        with self._lock:
            del self._ack_boxes[tid_str]

    def add_known_peer(self, addr: tuple):
        with self._lock:
            self._known_peers.add(addr)
            self._last_seen[addr] = time.time()

    def remove_known_peer(self, addr: tuple):
        with self._lock:
            self._known_peers.discard(addr)
            self._last_seen.pop(addr, None)

    def on_control(self, pkt_type: str, handler: Callable):
        """Register a callback for a specific control packet type."""
        self._control_handlers[pkt_type].append(handler)

    def stop(self):
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _recv_loop(self):
        self._sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception as e:
                log.debug("recv error: %s", e)
                continue

            with self._lock:
                self._last_seen[addr] = time.time()

            # Distinguish fragment packets from control JSON
            if len(data) >= HDR_SIZE and data.startswith(b"FRAG"):
                # Peek at the first 16+4+4+2 bytes; if it looks like a fragment, handle it
                try:
                    magic, tid, seq, total, flags = _HDR.unpack(data[:HDR_SIZE])
                    if flags & FLAG_ACK:
                        tid_str = tid.hex()
                        with self._lock:
                            ev = self._ack_boxes.get(tid_str, {}).get(seq)
                        if ev:
                            ev.set()
                        continue
                    # It's a data fragment — send ACK
                    ack = _HDR.pack(b"FRAG", tid, seq, total, FLAG_ACK)
                    self._sock.sendto(ack, addr)
                    self._reassemble(addr, tid, seq, total, flags, data[HDR_SIZE:])
                    continue
                except struct.error:
                    pass  # fall through to JSON

            # Try JSON control packet
            try:
                msg = json.loads(data)
                pkt_type = msg.get("type", "")
                if pkt_type == "ping":
                    self._sock.sendto(json.dumps({"type": "pong"}).encode(), addr)
                    continue
                if pkt_type == "pong":
                    continue  # last_seen already updated above
                handlers = self._control_handlers.get(pkt_type, [])
                for h in handlers:
                    try:
                        h(addr, msg)
                    except Exception as e:
                        log.debug("handler error for %s: %s", pkt_type, e)
                # Also pass to the generic on_message for the session layer
                self._on_message(addr, msg)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

    def _reassemble(self, addr, tid: bytes, seq: int, total: int, flags: int, body: bytes):
        tid_hex = tid.hex()
        meta    = None

        if flags & FLAG_META:
            # First two bytes of body are meta length
            if len(body) < 2:
                return
            mlen = struct.unpack(">H", body[:2])[0]
            try:
                meta = json.loads(body[2:2+mlen])
            except Exception:
                meta = {}
            body = body[2+mlen:]

        with self._lock:
            self._in_flight[tid_hex][seq] = body
            if meta is not None:
                self._in_totals[tid_hex + "_meta"] = meta
            if tid_hex not in self._in_totals:
                self._in_totals[tid_hex] = total
            total = self._in_totals[tid_hex]
            complete = len(self._in_flight[tid_hex]) == total
            if complete:
                frags = self._in_flight.pop(tid_hex)
                saved_meta = self._in_totals.pop(tid_hex + "_meta", {})
                self._in_totals.pop(tid_hex, None)

        if complete:
            payload = b"".join(frags[i] for i in range(total))
            msg = dict(saved_meta)
            msg["_payload_bytes"] = payload
            self._on_message(addr, msg)

    def _keepalive_loop(self):
        while self._running:
            time.sleep(self._ka_interval)
            now = time.time()
            with self._lock:
                peers = list(self._known_peers)
            for addr in peers:
                last = self._last_seen.get(addr, 0)
                if now - last > self._ka_dead_after:
                    self._on_peer_dead(addr)
                else:
                    try:
                        self._sock.sendto(json.dumps({"type": "ping"}).encode(), addr)
                    except Exception:
                        pass