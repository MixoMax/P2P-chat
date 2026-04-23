import sys
import os
import time
import socket
import threading
import logging

import config
from crypto import Identity, RelayIdentity
from store import MessageStore
from rendezvous import RendezvousClient
from transport import Transport
from session import SessionManager, PeerState
from relay import RelayManager

class HookedSocket:
    """
    Wraps the standard UDP socket so we can tap into all incoming packets.
    This resolves the architectural gap where pure encrypted binary chat packets 
    would otherwise be dropped by transport.py's JSON/Fragment parser.
    """
    def __init__(self, real_sock):
        self._sock = real_sock
        self.on_raw_inbound = None

    def sendto(self, data, addr):
        return self._sock.sendto(data, addr)

    def recvfrom(self, bufsize):
        data, addr = self._sock.recvfrom(bufsize)
        if self.on_raw_inbound:
            # Tap into raw bytes for SessionManager decryption
            self.on_raw_inbound(addr, data)
        return data, addr

    def settimeout(self, t):
        self._sock.settimeout(t)

    def getsockname(self):
        return self._sock.getsockname()


class SimpleUI:
    """
    A barebones CLI interface without curses.
    Supports basic connection, text sending, and an echo server mode for testing.
    """
    def __init__(self, name, on_send_chat, on_connect, on_quit):
        self.name = name
        self.on_send_chat = on_send_chat
        self.on_connect = on_connect
        self.on_quit = on_quit
        
        self.active_peer = None
        self.echo_mode = False

    def run(self):
        print(f"\n{'='*50}")
        print(f" P2P Chat Simple Debug UI - Logged in as: {self.name}")
        print(f"{'='*50}")
        print("Commands:")
        print("  /connect <peer>   - Connect to a peer")
        print("  /echo <on|off>    - Toggle auto-echo server mode")
        print("  /quit             - Shutdown client")
        print("  <text>            - Send message to active peer")
        print(f"{'='*50}\n")

        while True:
            try:
                line = input()
                if not line.strip(): 
                    continue
                
                parts = line.split(" ", 1)
                cmd = parts[0].lower()

                if cmd == "/connect":
                    if len(parts) > 1:
                        self.active_peer = parts[1].strip()
                        print(f"[*] Requesting connection to '{self.active_peer}'...")
                        # Run connect in background so we don't block input loop
                        threading.Thread(target=self.on_connect, args=(self.active_peer,), daemon=True).start()
                    else:
                        print("[!] Usage: /connect <peer>")
                
                elif cmd == "/echo":
                    if len(parts) > 1:
                        state = parts[1].strip().lower()
                        self.echo_mode = (state == "on")
                        print(f"[*] Echo mode: {'ON' if self.echo_mode else 'OFF'}")
                    else:
                        print("[!] Usage: /echo <on|off>")
                
                elif cmd == "/quit":
                    self.on_quit()
                    break
                
                elif cmd.startswith("/"):
                    print(f"[!] Unknown command: {cmd}")
                
                else:
                    if self.active_peer:
                        self.on_send_chat(self.active_peer, line)
                    else:
                        print("[!] No active peer. Use /connect <peer> first.")
            
            except (EOFError, KeyboardInterrupt):
                self.on_quit()
                break
            except Exception as e:
                print(f"[!] UI Input Error: {e}")

    def push_message(self, conv, sender, text, is_system=False, is_media=False, **kwargs):
        if is_system:
            print(f"\n[SYSTEM] {text}")
        elif is_media:
            print(f"\n[{sender}] sent a file: {kwargs.get('media_name', 'unknown')}")
        else:
            print(f"\n[{sender}] {text}")

        # Auto-echo logic
        if self.echo_mode and sender != self.name and not is_system and not is_media:
            logging.getLogger("ui").info("Auto-echoing message back to %s", conv)
            self.on_send_chat(conv, f"[ECHO] {text}")

    def add_peer(self, name):
        pass

    def update_peer_state(self, name, state):
        print(f"\n[*] Peer '{name}' state changed to: {state}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python main.py <name> <ui:default|simple>")
        sys.exit(1)

    my_name = sys.argv[1]
    ui_mode = sys.argv[2].lower()

    # Configure Heavy Logging for Simple Mode, file logging for TUI
    if ui_mode == "simple":
        logging.basicConfig(
            level=logging.DEBUG, 
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
    else:
        log_file = f"p2p_{my_name}_debug.log"
        logging.basicConfig(
            level=logging.DEBUG, 
            filename=log_file, 
            filemode="w",
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

    log = logging.getLogger("main")
    log.info("Booting P2P Client as '%s'", my_name)

    # 1. Init Config & Sockets
    config.load()
    real_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    real_sock.bind(("", 0))
    
    hooked_sock = HookedSocket(real_sock)
    my_priv_ip = socket.gethostbyname(socket.gethostname())
    my_priv_port = hooked_sock.getsockname()[1]

    # 2. Init Storage & Crypto
    my_identity = Identity(config.get("keys_dir"))
    relay_identity = RelayIdentity(config.get("keys_dir"))
    store = MessageStore()

    # 3. Connect to Rendezvous
    rendezvous = RendezvousClient(hooked_sock, my_name, my_identity.public_key_bytes, relay_identity.public_key_bytes)
    try:
        my_pub_addr = rendezvous.register([my_priv_ip, my_priv_port])
    except TimeoutError as e:
        log.error("Failed to register with rendezvous server: %s", e)
        sys.exit(1)

    ui_app = None  # Forward declaration for callbacks

    # 4. Session Layer Handlers
    def on_chat(peer_name, text, ts):
        if ui_app:
            ui_app.push_message(peer_name, peer_name, text)

    def on_media(peer_name, mime, name, data_bytes):
        if ui_app:
            ui_app.push_message(peer_name, peer_name, f"Received file: {name}", is_media=True, media_name=name, media_size=len(data_bytes))

    def on_state(peer_name, state):
        log.info("Connection state with %s is now %s", peer_name, state.name)
        if ui_app:
            ui_app.update_peer_state(peer_name, state.name)

    # 5. Transport Layer Handlers
    def on_transport_message(addr, msg):
        pass # Transport natively invokes control handlers directly.

    transport = Transport(hooked_sock, on_transport_message, on_peer_dead=lambda addr: session_mgr.mark_dead(addr))
    session_mgr = SessionManager(hooked_sock, my_name, my_identity, transport, on_chat, on_media, on_state)
    
    # Crucial: route raw inbound socket reads to decrypt raw chat messages 
    hooked_sock.on_raw_inbound = session_mgr.handle_raw

    # Route rendezvous packets caught by transport back to rendezvous client
    def on_rendezvous_msg(addr, msg):
        if addr == rendezvous.server_addr:
            if msg.get("type") in ("peer", "peer_online"):
                rendezvous.handle_message(msg)
                peer_name = msg.get("name")
                if peer_name:
                    info = {
                        "name":         peer_name,
                        "pub":          tuple(msg["pub"]),
                        "priv":         tuple(msg["priv"]),
                        "ed25519":      bytes.fromhex(msg["ed25519"]),
                        "relay_x25519": bytes.fromhex(msg["relay_x25519"]),
                    }
                    rendezvous.cache_peer(peer_name, info)
                    if msg.get("type") == "peer_online":
                        log.info("Peer %s is online, sending manifest if needed", peer_name)
                        relay_mgr.send_manifest(info)
                    
                    if not session_mgr.get_session(peer_name):
                        log.info("Received unsolicited intro for %s, starting connection", peer_name)
                        session_mgr.connect(info, my_pub_addr)
            elif msg.get("type") in ("error", "peer_list"):
                rendezvous.handle_message(msg)

    transport.on_control("peer", on_rendezvous_msg)
    transport.on_control("peer_online", on_rendezvous_msg)
    transport.on_control("error", on_rendezvous_msg)
    transport.on_control("peer_list", on_rendezvous_msg)

    # 6. Relay System Integration
    def on_relay_deliver(sender, plaintext_bytes, msg_id):
        text = plaintext_bytes.decode(errors='replace')
        log.info("Received stored relay message from %s (id: %s)", sender, msg_id)
        if ui_app:
            ui_app.push_message(sender, sender, text, is_system=True)

    relay_mgr = RelayManager(
        my_name, relay_identity, store,
        transport.send_dict, rendezvous.get_all_peers, on_relay_deliver
    )
    
    transport.on_control("relay", relay_mgr.handle_envelope)
    transport.on_control("relay_manifest", relay_mgr.handle_manifest)
    transport.on_control("relay_fetch_msg", relay_mgr.handle_fetch_msg)
    transport.on_control("relay_delete", relay_mgr.handle_delete)
    transport.on_control("relay_deliver", relay_mgr.handle_deliver)
    transport.on_control("relay_have", relay_mgr.handle_have)

    # 7. UI Actions (bound to ui_app)
    def ui_send_chat(peer, text):
        if not session_mgr.send_chat(peer, text):
            log.warning("Peer %s not READY. Attempting store-and-forward relay...", peer)
            peer_info = rendezvous.get_cached_peer(peer)
            if peer_info:
                relay_mgr.send(peer, peer_info["relay_x25519"], text.encode())
                log.info("Gossip envelope dispatched for %s", peer)
            else:
                log.error("Cannot relay to %s: Target unknown / no relay key cached", peer)

    def ui_send_file(peer, path):
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            session_mgr.send_media(peer, data, "application/octet-stream", os.path.basename(path))

    def ui_connect(peer_name):
        try:
            peer_info = rendezvous.get_cached_peer(peer_name)
            if not peer_info:
                peer_info = rendezvous.request_peer(peer_name)
            session_mgr.connect(peer_info, my_pub_addr)
        except Exception as e:
            log.error("Failed looking up %s: %s", peer_name, e)

    def ui_create_group(name, members):
        log.error("Groups are not supported in this client version.")

    def ui_refresh():
        peers = rendezvous.get_all_peers()
        for p in peers:
            rendezvous.cache_peer(p["name"], p)
            if ui_app:
                ui_app.add_peer(p["name"])

    def ui_quit():
        log.info("Shutting down...")
        transport.stop()
        sys.exit(0)

    # 8. Start UI App
    if ui_mode == "simple":
        ui_app = SimpleUI(my_name, ui_send_chat, ui_connect, ui_quit)
    else:
        from ui import TUI
        ui_app = TUI(
            my_name, ui_send_chat, ui_send_file, ui_connect, ui_create_group,
            ui_refresh, ui_quit,
            lambda: (store.current_size_bytes() / 1024 / 1024, config.get("relay_cache_limit_mb"))
        )

    # Blocks indefinitely based on UI loop
    ui_app.run()

if __name__ == "__main__":
    main()