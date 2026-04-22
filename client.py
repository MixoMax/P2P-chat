import socket
import json
import threading
import time
import sys
import uuid
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RENDEZVOUS = ("188.245.231.101", 10069)
MY_NAME = sys.argv[1] if len(sys.argv) > 1 else input("Enter your name: ")

# --- Cryptography Setup ---
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

MY_PRIV_KEY, MY_PUB_KEY = generate_keys()
MY_PUB_PEM = MY_PUB_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# --- State ---
mesh_peers = set() # Set of active (IP, Port) we are connected to
directory = {}     # {name: pubkey_pem}
groups = {}        # {group_name: [member_names]}
seen_messages = set() # UUIDs of messages we've already processed
message_cache = []    # Raw payloads to forward to new peers
active_chat = None    # context: string (name or group)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))

print_lock = threading.Lock()

def ui_print(text):
    with print_lock:
        sys.stdout.write(f"\r\033[K{text}\n> ")
        sys.stdout.flush()

# --- Crypto Helpers ---
def load_pubkey(pem_str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))

def encrypt_message(text, recipient_names):
    """Encrypts a message for a list of recipients."""
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    
    # Encrypt the AES key for each recipient
    encrypted_keys = {}
    for r in recipient_names:
        if r not in directory: continue
        pubkey = load_pubkey(directory[r]["pubkey"])
        enc_aes = pubkey.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted_keys[r] = base64.b64encode(enc_aes).decode('utf-8')
    
    # Sign the ciphertext
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
    """Attempts to decrypt a received gossip payload."""
    enc_keys = msg_data["encrypted_keys"]
    if MY_NAME not in enc_keys:
        return None # Not meant for us
    
    try:
        # Decrypt AES key
        enc_aes = base64.b64decode(enc_keys[MY_NAME])
        aes_key = MY_PRIV_KEY.decrypt(
            enc_aes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        # Decrypt Ciphertext
        aesgcm = AESGCM(aes_key)
        nonce = base64.b64decode(msg_data["nonce"])
        ciphertext = base64.b64decode(msg_data["ciphertext"])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Verify Signature (Find sender pubkey)
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
    except Exception as e:
        return f"[Decryption/Signature Error: {e}]"
    return None

# --- Networking Core ---
def send_to_rendezvous(data):
    sock.sendto(json.dumps(data).encode(), RENDEZVOUS)

def gossip_broadcast(payload, exclude_addr=None):
    """Send payload to all connected mesh peers."""
    data = json.dumps(payload).encode()
    for p in list(mesh_peers):
        if p != exclude_addr:
            try:
                sock.sendto(data, p)
            except Exception:
                pass

def network_listener():
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data)
            mtype = msg.get("type")

            if addr == RENDEZVOUS:
                if mtype == "directory":
                    global directory
                    directory = msg["users"]
                    ui_print("[System] Directory updated.")
                
                elif mtype == "punch_target":
                    target = tuple(msg["target"])
                    mesh_peers.add(target)
                    # Send a UDP hole punch to the target
                    sock.sendto(json.dumps({"type": "punch"}).encode(), target)
                    # Sync local cache to new peer
                    for cached_msg in message_cache:
                        sock.sendto(json.dumps(cached_msg).encode(), target)

            else:
                # Messages from mesh peers
                if mtype == "punch":
                    mesh_peers.add(addr)
                
                elif mtype == "gossip":
                    msg_id = msg["msg_id"]
                    if msg_id in seen_messages:
                        continue # Already processed
                    
                    seen_messages.add(msg_id)
                    message_cache.append(msg)
                    
                    # Forward to everyone else
                    gossip_broadcast(msg, exclude_addr=addr)

                    # Try to read it
                    plaintext = try_decrypt(msg)
                    if plaintext:
                        sender = msg["sender"]
                        group = msg.get("group_id")
                        context = f"{sender} in {group}" if group else sender
                        ui_print(f"[{context}]: {plaintext}")

        except Exception as e:
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

# --- CLI ---
time.sleep(1) # Wait for initial directory sync
ui_print(f"Logged in as {MY_NAME}.")
ui_print("Commands: /users, /groups, /group create <name> <u1,u2...>, /chat <name>, /quit")

while True:
    try:
        sys.stdout.write("> ")
        sys.stdout.flush()
        text = sys.stdin.readline().strip()
        if not text: continue

        if text.startswith("/users"):
            ui_print("--- Directory ---")
            for u, info in directory.items():
                status = "Online" if info["online"] else "Offline"
                ui_print(f"  {u} [{status}]")
        
        elif text.startswith("/groups"):
            ui_print("--- Groups ---")
            for g, members in groups.items():
                ui_print(f"  {g}: {', '.join(members)}")
        
        elif text.startswith("/group create"):
            _, _, gname, gmembers = text.split(" ", 3)
            members = [m.strip() for m in gmembers.split(",")]
            members.append(MY_NAME) # Include self
            groups[gname] = members
            ui_print(f"Group '{gname}' created locally.")

        elif text.startswith("/chat"):
            _, target = text.split(" ", 1)
            if target in directory or target in groups:
                active_chat = target
                ui_print(f"Now chatting with {target}")
            else:
                ui_print("User/Group not found.")
        
        elif text == "/quit":
            break

        else:
            # Send message
            if not active_chat:
                ui_print("No active chat. Use /chat <name> first.")
                continue
            
            is_group = active_chat in groups
            recipients = groups[active_chat] if is_group else [active_chat, MY_NAME]
            
            # Check if all recipients exist
            missing = [r for r in recipients if r not in directory]
            if missing:
                ui_print(f"Cannot send, missing public keys for: {', '.join(missing)}")
                continue

            payload = encrypt_message(text, recipients)
            msg_id = str(uuid.uuid4())
            gossip_envelope = {
                "type": "gossip",
                "msg_id": msg_id,
                "sender": MY_NAME,
                "group_id": active_chat if is_group else None,
                **payload
            }

            # Process our own message so it goes into history/cache
            seen_messages.add(msg_id)
            message_cache.append(gossip_envelope)
            
            # Send to network
            gossip_broadcast(gossip_envelope)
            ui_print(f"[Me -> {active_chat}]: {text}")

    except KeyboardInterrupt:
        break
    except Exception as e:
        ui_print(f"Error: {e}")