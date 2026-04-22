import socket, json, threading, time, sys, uuid, base64, os, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- OS-Specific Input Handling (Standard Library Only) ---
if os.name == 'nt':
    import msvcrt
    def get_key():
        return msvcrt.getch()
else:
    import termios, tty
    def get_key():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch.encode()

# --- Config & Keys ---
RENDEZVOUS = ("188.245.231.101", 10069)
MY_NAME = input("Name: ")
MY_PASS = input("Password: ")

def generate_keys():
    priv = rsa.generate_private_key(65537, 2048)
    return priv, priv.public_key()

MY_PRIV_KEY, MY_PUB_KEY = generate_keys()
MY_PUB_PEM = MY_PUB_KEY.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# --- State ---
mesh_peers, directory, groups, seen_messages, message_cache = set(), {}, {}, set(), []
active_chat, input_buffer = None, ""
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))

def ui_print(text):
    sys.stdout.write(f"\r\033[K{text}\n> {input_buffer}")
    sys.stdout.flush()

# [Encryption helpers remain identical to previous version...]
def load_pubkey(p): return serialization.load_pem_public_key(p.encode())
def encrypt_message(text, recipients):
    key = AESGCM.generate_key(256); aes = AESGCM(key); nonce = os.urandom(12)
    ct = aes.encrypt(nonce, text.encode(), None)
    e_keys = {}
    for r in recipients:
        if r not in directory: continue
        enc_k = load_pubkey(directory[r]["pubkey"]).encrypt(key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        e_keys[r] = base64.b64encode(enc_k).decode()
    sig = MY_PRIV_KEY.sign(ct, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode(), "encrypted_keys": e_keys, "signature": base64.b64encode(sig).decode()}

def try_decrypt(msg):
    try:
        if MY_NAME not in msg["encrypted_keys"]: return None
        key = MY_PRIV_KEY.decrypt(base64.b64decode(msg["encrypted_keys"][MY_NAME]), padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        pt = AESGCM(key).decrypt(base64.b64decode(msg["nonce"]), base64.b64decode(msg["ciphertext"]), None)
        load_pubkey(directory[msg["sender"]]["pubkey"]).verify(base64.b64decode(msg["signature"]), base64.b64decode(msg["ciphertext"]), padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
        return pt.decode()
    except: return None

# --- Networking ---
def network_listener():
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data)
            if addr == RENDEZVOUS:
                if msg["type"] == "directory": 
                    global directory; directory = msg["users"]
                elif msg["type"] == "punch_target":
                    t = tuple(msg["target"])
                    mesh_peers.add(t)
                    sock.sendto(json.dumps({"type":"punch"}).encode(), t)
            else:
                if msg["type"] == "gossip" and msg["msg_id"] not in seen_messages:
                    seen_messages.add(msg["msg_id"])
                    message_cache.append(msg)
                    for p in list(mesh_peers): 
                        if p != addr: sock.sendto(data, p)
                    pt = try_decrypt(msg)
                    if pt: ui_print(f"[{msg['sender']}]: {pt}")
        except: pass

threading.Thread(target=network_listener, daemon=True).start()

# --- Registration & Auth ---
sock.sendto(json.dumps({"type": "register", "name": MY_NAME, "password": MY_PASS, "pubkey": MY_PUB_PEM}).encode(), RENDEZVOUS)

def sync_loop():
    while True:
        sock.sendto(json.dumps({"type": "get_directory"}).encode(), RENDEZVOUS)
        sock.sendto(json.dumps({"type": "request_mesh", "name": MY_NAME}).encode(), RENDEZVOUS)
        time.sleep(15)

threading.Thread(target=sync_loop, daemon=True).start()

# --- Hotkey CLI Logic ---
ui_print("SYSTEM: Ctrl+L: List Users | Ctrl+C: Exit | Enter: Send")
ui_print("To chat: Type /chat <name> and press Enter.")

while True:
    k = get_key()
    
    # Handle Hotkeys
    if k == b'\x0c': # Ctrl + L
        ui_print(f"ONLINE: {', '.join([u for u,i in directory.items() if i['online']])}")
    elif k in (b'\x03', b'\x11'): # Ctrl + C or Ctrl + Q
        break
    elif k in (b'\r', b'\n'): # Enter
        cmd = input_buffer.strip()
        if cmd.startswith("/chat "):
            active_chat = cmd.split(" ")[1]
            ui_print(f"SYSTEM: Chatting with {active_chat}")
        elif active_chat and cmd:
            recipients = [active_chat, MY_NAME]
            if all(r in directory for r in recipients):
                payload = encrypt_message(cmd, recipients)
                mid = str(uuid.uuid4())
                env = {"type":"gossip", "msg_id":mid, "sender":MY_NAME, **payload}
                seen_messages.add(mid)
                for p in list(mesh_peers): sock.sendto(json.dumps(env).encode(), p)
                ui_print(f"[Me -> {active_chat}]: {cmd}")
            else: ui_print("ERROR: User offline or unknown.")
        input_buffer = ""
        sys.stdout.write(f"\r\033[K> ")
    elif k == b'\x08' or k == b'\x7f': # Backspace
        input_buffer = input_buffer[:-1]
        sys.stdout.write(f"\r\033[K> {input_buffer}")
    else:
        try:
            char = k.decode()
            if char.isprintable():
                input_buffer += char
                sys.stdout.write(char)
        except: pass
    sys.stdout.flush()