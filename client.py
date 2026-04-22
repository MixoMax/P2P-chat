import socket
import json
import threading
import time
import sys
import uuid
import base64
import os
import hashlib
import getpass
import curses
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RENDEZVOUS = ("188.245.231.101", 10069)

# --- Bootup & Security ---
print("--- P2P Secure Chat ---")
MY_NAME = input("Username: ").strip()
MY_PASSWORD = getpass.getpass("Password: ")
PWD_HASH = hashlib.sha256(MY_PASSWORD.encode()).hexdigest()

key_filename = f"{MY_NAME}_priv.pem"

if os.path.exists(key_filename):
    print("Loading existing encrypted profile...")
    with open(key_filename, "rb") as f:
        try:
            MY_PRIV_KEY = serialization.load_pem_private_key(
                f.read(), password=MY_PASSWORD.encode()
            )
            MY_PUB_KEY = MY_PRIV_KEY.public_key()
        except ValueError:
            print("Error: Incorrect password or corrupted key file.")
            sys.exit(1)
else:
    print("Generating new profile and keys...")
    MY_PRIV_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    MY_PUB_KEY = MY_PRIV_KEY.public_key()
    # Save encrypted locally
    pem_data = MY_PRIV_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(MY_PASSWORD.encode())
    )
    with open(key_filename, "wb") as f:
        f.write(pem_data)

MY_PUB_PEM = MY_PUB_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# --- State ---
mesh_peers = set()
directory = {}     
groups = {}        
seen_messages = set() 
message_cache = []    

# UI State
chat_history = defaultdict(list) # {target_name: ["msg1", "msg2"]}
ui_lock = threading.Lock()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))

# --- Crypto Helpers ---
def load_pubkey(pem_str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))

def encrypt_message(text, recipient_names):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    
    encrypted_keys = {}
    for r in recipient_names:
        if r not in directory: continue
        pubkey = load_pubkey(directory[r]["pubkey"])
        enc_aes = pubkey.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted_keys[r] = base64.b64encode(enc_aes).decode('utf-8')
    
    signature = MY_PRIV_KEY.sign(
        ciphertext,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "encrypted_keys": encrypted_keys,
        "signature": base64.b64encode(signature).decode('utf-8')
    }

def try_decrypt(msg_data):
    enc_keys = msg_data["encrypted_keys"]
    if MY_NAME not in enc_keys:
        return None
    try:
        enc_aes = base64.b64decode(enc_keys[MY_NAME])
        aes_key = MY_PRIV_KEY.decrypt(
            enc_aes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        aesgcm = AESGCM(aes_key)
        nonce = base64.b64decode(msg_data["nonce"])
        ciphertext = base64.b64decode(msg_data["ciphertext"])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        sender = msg_data["sender"]
        if sender in directory:
            sender_pub = load_pubkey(directory[sender]["pubkey"])
            signature = base64.b64decode(msg_data["signature"])
            sender_pub.verify(
                signature,
                ciphertext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return plaintext.decode('utf-8')
    except Exception:
        pass
    return None

# --- Networking Core ---
def send_to_rendezvous(data):
    data["pwd_hash"] = PWD_HASH # Always append auth
    sock.sendto(json.dumps(data).encode(), RENDEZVOUS)

def gossip_broadcast(payload, exclude_addr=None):
    data = json.dumps(payload).encode()
    for p in list(mesh_peers):
        if p != exclude_addr:
            try: sock.sendto(data, p)
            except Exception: pass

def network_listener():
    global directory
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data)
            mtype = msg.get("type")

            if addr == RENDEZVOUS:
                if mtype == "error":
                    with ui_lock:
                        chat_history["System"].append(f"[SERVER ERROR]: {msg.get('msg')}")
                elif mtype == "directory":
                    directory = msg["users"]
                elif mtype == "punch_target":
                    target = tuple(msg["target"])
                    mesh_peers.add(target)
                    sock.sendto(json.dumps({"type": "punch"}).encode(), target)
                    for cached_msg in message_cache:
                        sock.sendto(json.dumps(cached_msg).encode(), target)

            else:
                if mtype == "punch":
                    mesh_peers.add(addr)
                elif mtype == "gossip":
                    msg_id = msg["msg_id"]
                    if msg_id in seen_messages: continue
                    
                    seen_messages.add(msg_id)
                    message_cache.append(msg)
                    gossip_broadcast(msg, exclude_addr=addr)

                    plaintext = try_decrypt(msg)
                    if plaintext:
                        sender = msg["sender"]
                        group = msg.get("group_id")
                        context = group if group else sender
                        with ui_lock:
                            chat_history[context].append(f"[{sender}]: {plaintext}")

        except Exception:
            pass

threading.Thread(target=network_listener, daemon=True).start()

# --- Lifecycle ---
send_to_rendezvous({"type": "register", "name": MY_NAME, "pubkey": MY_PUB_PEM})

def keep_alive_and_sync():
    while True:
        send_to_rendezvous({"type": "ping", "name": MY_NAME})
        send_to_rendezvous({"type": "get_directory"})
        send_to_rendezvous({"type": "request_mesh", "name": MY_NAME})
        time.sleep(15)

threading.Thread(target=keep_alive_and_sync, daemon=True).start()

# --- Terminal UI Core ---
def send_msg(text, active_chat):
    if not active_chat or active_chat == "System":
        return

    is_group = active_chat in groups
    recipients = groups[active_chat] if is_group else [active_chat, MY_NAME]
    
    missing = [r for r in recipients if r not in directory]
    if missing:
        chat_history["System"].append(f"Cannot send, missing keys for: {', '.join(missing)}")
        return

    payload = encrypt_message(text, recipients)
    msg_id = str(uuid.uuid4())
    gossip_envelope = {
        "type": "gossip",
        "msg_id": msg_id,
        "sender": MY_NAME,
        "group_id": active_chat if is_group else None,
        **payload
    }

    seen_messages.add(msg_id)
    message_cache.append(gossip_envelope)
    gossip_broadcast(gossip_envelope)
    
    with ui_lock:
        chat_history[active_chat].append(f"[Me]: {text}")

def tui_loop(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)

    input_buffer = ""
    selected_idx = 0

    while True:
        # Build targets: System + Users + Groups
        with ui_lock:
            targets = ["System"] + [u for u in directory if u != MY_NAME] + list(groups.keys())
        
        if selected_idx >= len(targets): selected_idx = max(0, len(targets) - 1)
        active_chat = targets[selected_idx] if targets else "None"

        c = stdscr.getch()
        if c != -1:
            if c == curses.KEY_UP:
                selected_idx = max(0, selected_idx - 1)
            elif c == curses.KEY_DOWN:
                selected_idx = min(len(targets) - 1, selected_idx + 1)
            elif c in (curses.KEY_BACKSPACE, 127, 8, '\b'):
                input_buffer = input_buffer[:-1]
            elif c == 10 or c == 13: # Enter
                if input_buffer.strip():
                    send_msg(input_buffer, active_chat)
                    input_buffer = ""
            elif c == curses.KEY_F2:
                # Group Creation popup
                stdscr.nodelay(False)
                curses.echo()
                h, w = stdscr.getmaxyx()
                stdscr.addstr(h - 1, 0, " " * (w - 1)) # clear line
                stdscr.addstr(h - 1, 0, "[New Group] Name: ")
                gname = stdscr.getstr(h - 1, 18).decode('utf-8').strip()
                stdscr.addstr(h - 1, 0, " " * (w - 1))
                stdscr.addstr(h - 1, 0, "[New Group] Members (comma sep): ")
                gmembers = stdscr.getstr(h - 1, 33).decode('utf-8')
                curses.noecho()
                stdscr.nodelay(True)
                
                if gname:
                    members = [m.strip() for m in gmembers.split(",") if m.strip()]
                    members.append(MY_NAME)
                    with ui_lock:
                        groups[gname] = members
                        chat_history["System"].append(f"Group '{gname}' created locally.")
            elif c == 27: # ESC key to quit
                break
            elif 32 <= c <= 126:
                input_buffer += chr(c)

        # Drawing
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        left_w = 25

        # Draw Left Pane
        stdscr.addstr(0, 0, "Users & Groups (F2)", curses.A_BOLD)
        for i, tgt in enumerate(targets):
            if i + 1 >= h - 3: break
            prefix = ">>" if i == selected_idx else "  "
            
            # Show online status for users
            status = ""
            if tgt in directory and tgt != "System":
                status = "(*)" if directory[tgt].get("online") else "( )"
            
            disp_str = f"{prefix} {tgt} {status}"[:left_w-1]
            attr = curses.A_REVERSE if i == selected_idx else curses.A_NORMAL
            stdscr.addstr(i + 1, 0, disp_str, attr)

        # Draw Divider
        for i in range(h - 2):
            stdscr.addch(i, left_w, '|')

        # Draw Chat History
        with ui_lock:
            history = chat_history[active_chat]
        
        start_y = h - 4
        for msg in reversed(history):
            if start_y < 0: break
            safe_msg = msg[:w - left_w - 3]
            stdscr.addstr(start_y, left_w + 2, safe_msg)
            start_y -= 1

        # Draw Input Area
        stdscr.hline(h - 2, 0, '-', w)
        prompt_str = f"To [{active_chat}]: {input_buffer}"
        stdscr.addstr(h - 1, 0, prompt_str[:w-1])
        
        stdscr.refresh()

# Start UI
try:
    curses.wrapper(tui_loop)
except KeyboardInterrupt:
    pass