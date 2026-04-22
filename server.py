import socket
import json
import threading
import time
import hashlib
import os

# {name: {"pubkey": str, "addr": (ip, port), "last_seen": float, "hash": str, "salt": str}}
peers = {}  
lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return dk.hex(), salt

def clean_stale_peers():
    while True:
        time.sleep(15)
        now = time.time()
        with lock:
            for name, info in list(peers.items()):
                if info.get("addr") and now - info["last_seen"] > 60:
                    info["addr"] = None

threading.Thread(target=clean_stale_peers, daemon=True).start()

print("Secure Rendezvous Server listening on :10069")

while True:
    data, addr = sock.recvfrom(65535)
    try:
        msg = json.loads(data)
        mtype = msg.get("type")
    except: continue

    with lock:
        now = time.time()
        if mtype == "register":
            name, password = msg["name"], msg["password"]
            pubkey = msg["pubkey"]
            
            if name in peers:
                # Verify existing user
                target_hash, _ = hash_password(password, peers[name]["salt"])
                if target_hash == peers[name]["hash"]:
                    peers[name].update({"addr": addr, "last_seen": now, "pubkey": pubkey})
                    response = {"type": "auth_success", "status": "reconnected"}
                else:
                    response = {"type": "error", "message": "Invalid password for this name."}
            else:
                # Create new user
                pw_hash, pw_salt = hash_password(password)
                peers[name] = {"pubkey": pubkey, "addr": addr, "last_seen": now, "hash": pw_hash, "salt": pw_salt}
                response = {"type": "auth_success", "status": "registered"}
            
            sock.sendto(json.dumps(response).encode(), addr)

        elif mtype == "get_directory":
            directory = {n: {"pubkey": i["pubkey"], "online": i["addr"] is not None} for n, i in peers.items()}
            sock.sendto(json.dumps({"type": "directory", "users": directory}).encode(), addr)

        elif mtype == "request_mesh":
            name = msg.get("name")
            online = [i["addr"] for n, i in peers.items() if i["addr"] and n != name]
            for target in online[:5]:
                sock.sendto(json.dumps({"type": "punch_target", "target": target}).encode(), addr)
                sock.sendto(json.dumps({"type": "punch_target", "target": addr}).encode(), target)