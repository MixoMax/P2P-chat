"""
main.py — entry point.  Wires all modules together.

Usage:
  python main.py <your-name> [--config path/to/config.json]
                             [--rendezvous host:port]
                             [--relay-cache 512]   (MB)
"""

import argparse, base64, json, logging, mimetypes, os, socket
import sys, threading, time
from pathlib import Path

import config as cfg
import crypto, rendezvous as rdv, store, relay as rly
import session as sess_mod, transport, ui as ui_mod

logging.basicConfig(
    filename=os.path.expanduser("~/.p2p-chat/debug.log"),
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("main")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--config", default=None)
    ap.add_argument("--rendezvous", default=None)
    ap.add_argument("--relay-cache", type=int, default=None)
    args = ap.parse_args()

    # ── Load config ───────────────────────────────────────────────────────────
    config = cfg.load(args.config)
    if args.rendezvous:
        host, port = args.rendezvous.rsplit(":", 1)
        config["rendezvous_host"] = host
        config["rendezvous_port"] = int(port)
    if args.relay_cache:
        config["relay_cache_limit_mb"] = args.relay_cache

    MY_NAME = args.name

    # ── Crypto identity ───────────────────────────────────────────────────────
    identity       = crypto.Identity(cfg.get("keys_dir"))
    relay_identity = crypto.RelayIdentity(cfg.get("keys_dir"))

    # ── UDP socket ────────────────────────────────────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    my_priv_ip   = socket.gethostbyname(socket.gethostname())
    my_priv_port = sock.getsockname()[1]
    priv_addr    = [my_priv_ip, my_priv_port]
    log.info("Bound to %s:%d", my_priv_ip, my_priv_port)

    # ── Rendezvous ────────────────────────────────────────────────────────────
    rend = rdv.RendezvousClient(
        sock, MY_NAME,
        ed25519_pub    = identity.public_key_bytes,
        relay_x25519_pub = relay_identity.public_key_bytes,
    )
    my_pub = rend.register(priv_addr)

    # ── Message store ─────────────────────────────────────────────────────────
    msg_store = store.MessageStore()

    # ── UI (constructed early so we can push messages into it from callbacks) ─
    tui = ui_mod.TUI(
        my_name       = MY_NAME,
        on_send_chat  = lambda peer, text: _send_chat(peer, text),
        on_send_file  = lambda peer, path: _send_file(peer, path),
        on_connect    = lambda peer: _connect_peer(peer),
        on_create_group = lambda name, members: _create_group(name, members),
        on_refresh    = lambda: _refresh_peers(),
        on_quit       = lambda: _quit(),
        relay_cache_fn = lambda: (
            msg_store.current_size_bytes() / 1024 / 1024,
            cfg.get("relay_cache_limit_mb"),
        ),
    )

    # ── Transport ─────────────────────────────────────────────────────────────
    def _on_raw_message(addr, msg):
        """Called for every inbound packet (control OR reassembled large payload)."""
        pkt_type = msg.get("type", "")

        if pkt_type == "relay":
            relay_mgr.handle_envelope(addr, msg)
        elif pkt_type == "relay_fetch":
            relay_mgr.handle_fetch(addr, msg)
        elif pkt_type == "relay_deliver":
            relay_mgr.handle_deliver(addr, msg)
        elif pkt_type == "relay_have":
            relay_mgr.handle_have(addr, msg)
        elif pkt_type == "media":
            # Reassembled large payload
            data  = msg.get("_payload_bytes", b"")
            peer  = _addr_to_peer(addr)
            mime  = msg.get("mime", "application/octet-stream")
            name  = msg.get("name", "file")
            if peer:
                _save_media(peer, mime, name, data)
        # Other types (chat, punch, hs_*) are handled by SessionManager

    def _on_peer_dead(addr):
        sess_mgr.mark_dead(addr)

    tx = transport.Transport(sock, _on_raw_message, _on_peer_dead)

    # ── Session manager ───────────────────────────────────────────────────────
    def _on_chat(peer_name, text, ts):
        tui.push_message(peer_name, peer_name, text)

    def _on_media(peer_name, mime, name, data):
        tui.push_message(peer_name, peer_name,
                         is_media=True, media_name=name, media_size=len(data),
                         media_progress=-1)
        _save_media(peer_name, mime, name, data)

    def _on_state(peer_name, state):
        state_str = state.name if hasattr(state, "name") else str(state)
        tui.update_peer_state(peer_name, state_str)
        if state_str == "READY":
            tui.push_message(peer_name, "", f"{peer_name} connected", is_system=True)

    sess_mgr = sess_mod.SessionManager(
        sock, MY_NAME, identity, tx,
        on_chat  = _on_chat,
        on_media = _on_media,
        on_state = _on_state,
    )

    # ── Known peer tracking (for relay gossip) ────────────────────────────────
    _known_peers: list[dict] = []   # {"name", "pub", "relay_x25519", ...}
    _peers_lock  = threading.Lock()

    def _get_all_peers():
        with _peers_lock:
            return list(_known_peers)

    def _update_known_peers(peers_list):
        with _peers_lock:
            for p in peers_list:
                if p["name"] != MY_NAME:
                    if not any(x["name"] == p["name"] for x in _known_peers):
                        _known_peers.append(p)
                    tui.add_peer(p["name"])

    # ── Relay manager ─────────────────────────────────────────────────────────
    def _on_relay_deliver(sender, plaintext, msg_id):
        try:
            msg  = json.loads(plaintext)
            conv = msg.get("group", sender)
            text = msg.get("text", "")
            tui.push_message(conv, sender, text)
            tui.push_message(conv, "", f"(delivered via relay)", is_system=True)
        except Exception as e:
            log.debug("relay deliver parse error: %s", e)

    relay_mgr = rly.RelayManager(
        my_name          = MY_NAME,
        relay_identity   = relay_identity,
        store            = msg_store,
        send_fn          = tx.send_dict,
        get_all_peers_fn = _get_all_peers,
        on_deliver       = _on_relay_deliver,
    )

    # ── Helper: addr → peer name ───────────────────────────────────────────────
    def _addr_to_peer(addr):
        s = sess_mgr.all_sessions()
        for name, ps in s.items():
            if ps.addr == addr:
                return name
        return None

    # ── Action callbacks (called from TUI) ────────────────────────────────────
    def _connect_peer(peer_name: str):
        """Called when user selects a peer in the list."""
        s = sess_mgr.get_session(peer_name)
        if s:
            return   # already connected or connecting
        # Look up peer info
        info = rend.get_cached_peer(peer_name)
        if not info:
            try:
                info = rend.request_peer(peer_name)
            except Exception as e:
                tui.push_message(peer_name, "", f"Could not reach {peer_name}: {e}", is_system=True)
                return
        info["name"] = peer_name
        tui.update_peer_state(peer_name, "PUNCHING")
        sess_mgr.connect(info, my_pub)

    def _send_chat(peer: str, text: str):
        # First try direct session
        if sess_mgr.send_chat(peer, text):
            return
        # Peer offline — send via relay
        peer_info = rend.get_cached_peer(peer)
        if not peer_info:
            try:
                peer_info = rend.request_peer(peer)
            except Exception:
                pass
        if peer_info:
            plaintext = json.dumps({"text": text, "ts": time.time()}).encode()
            relay_mgr.send(peer, peer_info["relay_x25519"], plaintext)
            tui.push_message(peer, "", "(sent via relay — peer offline)", is_system=True)
        else:
            tui.push_message(peer, "", "Peer not reachable and not registered", is_system=True)

    def _send_file(peer: str, path: str):
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            tui.push_message(peer, "", f"File not found: {path}", is_system=True)
            return
        size = os.path.getsize(path)
        name = os.path.basename(path)
        mime, _ = mimetypes.guess_type(path)
        mime = mime or "application/octet-stream"

        tui.push_message(peer, "you", is_media=True, media_name=name,
                         media_size=size, media_progress=0)

        def _do():
            with open(path, "rb") as f:
                data = f.read()
            ok = sess_mgr.send_media(peer, data, mime, name)
            if ok:
                tui.set_media_progress(peer, name, -1)
            else:
                tui.push_message(peer, "", f"Cannot send {name} — peer not ready", is_system=True)

        threading.Thread(target=_do, daemon=True).start()

    def _create_group(name: str, members: list[str]):
        import uuid
        gid = str(uuid.uuid4())
        tui.add_group(gid, name, members)
        # Notify members
        announce = json.dumps({
            "type":    "group_add",
            "gid":     gid,
            "name":    name,
            "members": members,
        }).encode()
        for m in members:
            if m == MY_NAME:
                continue
            peer_info = rend.get_cached_peer(m)
            if peer_info:
                relay_mgr.send(m, peer_info["relay_x25519"], announce)
        tui.push_message(name, "", f"Group #{name} created with {len(members)} members", is_system=True)

    def _refresh_peers():
        def _do():
            peers = rend.get_all_peers()
            _update_known_peers(peers)
            # Announce online to all known peers (triggers relay delivery)
            addrs = [tuple(p["pub"]) for p in peers if p["name"] != MY_NAME]
            relay_mgr.announce_online(addrs)
        threading.Thread(target=_do, daemon=True).start()

    def _quit():
        tx.stop()
        sys.exit(0)

    def _save_media(peer: str, mime: str, name: str, data: bytes):
        dl_dir = Path.home() / "Downloads" / "p2p-chat"
        dl_dir.mkdir(parents=True, exist_ok=True)
        out = dl_dir / name
        # Avoid overwriting
        stem, suf = out.stem, out.suffix
        i = 1
        while out.exists():
            out = dl_dir / f"{stem}_{i}{suf}"
            i += 1
        out.write_bytes(data)
        tui.push_message(peer, "", f"Saved: {out}", is_system=True)

    # ── Initial peer refresh ──────────────────────────────────────────────────
    _refresh_peers()

    # ── Handle group_add relay messages ──────────────────────────────────────
    orig_deliver = _on_relay_deliver.__code__

    def _on_relay_deliver_extended(sender, plaintext, msg_id):
        try:
            msg = json.loads(plaintext)
            if msg.get("type") == "group_add":
                gid     = msg["gid"]
                gname   = msg["name"]
                members = msg["members"]
                tui.add_group(gid, gname, members)
                tui.push_message(gname, "", f"Added to group #{gname} by {sender}", is_system=True)
                return
            conv = msg.get("group", sender)
            text = msg.get("text", "")
            tui.push_message(conv, sender, text)
            tui.push_message(conv, "", "(delivered via relay)", is_system=True)
        except Exception as e:
            log.debug("relay deliver parse error: %s", e)

    relay_mgr._on_deliver = _on_relay_deliver_extended

    # ── Run TUI (blocks until quit) ───────────────────────────────────────────
    tui.run()


if __name__ == "__main__":
    main()