import socket
import json
import threading
import time

# peers struct: {name: {"pubkey": str, "addr": (ip, port), "last_seen": float, "pwd_hash": str}}
peers = {}  
lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))

print("Rendezvous server listening on :10069")

def clean_stale_peers():
    while True:
        time.sleep(10)
        now = time.time()
        with lock:
            for name, info in list(peers.items()):
                if info.get("addr") and now - info["last_seen"] > 60:
                    print(f"[{name}] went offline.")
                    info["addr"] = None

threading.Thread(target=clean_stale_peers, daemon=True).start()

def introduce(addr_a, addr_b):
    sock.sendto(json.dumps({"type": "punch_target", "target": addr_b}).encode(), addr_a)

while True:
    data, addr = sock.recvfrom(65535)
    try:
        msg = json.loads(data)
    except json.JSONDecodeError:
        continue

    with lock:
        now = time.time()
        msg_type = msg.get("type")
        name = msg.get("name")
        pwd_hash = msg.get("pwd_hash", "")

        if msg_type == "register":
            pubkey = msg.get("pubkey")
            
            # Security check: Does user exist, and if so, does the password match?
            if name in peers:
                if peers[name]["pwd_hash"] != pwd_hash:
                    error_msg = json.dumps({"type": "error", "msg": "Username taken or invalid password"}).encode()
                    sock.sendto(error_msg, addr)
                    continue
                else:
                    peers[name]["pubkey"] = pubkey
                    peers[name]["addr"] = addr
                    peers[name]["last_seen"] = now
            else:
                peers[name] = {"pubkey": pubkey, "addr": addr, "last_seen": now, "pwd_hash": pwd_hash}
                
            sock.sendto(json.dumps({"type": "registered"}).encode(), addr)
            print(f"Registered/Authenticated {name} at {addr}")

        # For all state-altering commands, strictly enforce auth checks
        elif msg_type in ["ping", "get_directory", "request_mesh"]:
            if name in peers and peers[name]["pwd_hash"] == pwd_hash:
                peers[name]["addr"] = addr
                peers[name]["last_seen"] = now
                
                if msg_type == "get_directory":
                    directory = {
                        n: {"pubkey": i["pubkey"], "online": i["addr"] is not None}
                        for n, i in peers.items()
                    }
                    sock.sendto(json.dumps({"type": "directory", "users": directory}).encode(), addr)
                    
                elif msg_type == "request_mesh":
                    online_addrs = [i["addr"] for n, i in peers.items() if i["addr"] and n != name]
                    for target_addr in online_addrs[:5]:
                        introduce(addr, target_addr)
                        introduce(target_addr, addr)