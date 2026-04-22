import socket
import json
import threading
import time

peers = {}  # {name: {"pubkey": str, "addr": (ip, port), "last_seen": float}}
lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))

print("Rendezvous server listening on :10069")

def clean_stale_peers():
    """Mark peers offline if they haven't pinged in 60 seconds."""
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
    """Tell two nodes to punch holes to each other."""
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

        if msg_type == "register":
            name = msg["name"]
            pubkey = msg["pubkey"]
            if name not in peers:
                peers[name] = {"pubkey": pubkey, "addr": addr, "last_seen": now}
            else:
                peers[name]["addr"] = addr
                peers[name]["last_seen"] = now
            
            sock.sendto(json.dumps({"type": "registered"}).encode(), addr)
            print(f"Registered/Seen {name} at {addr}")

        elif msg_type == "ping":
            name = msg.get("name")
            if name in peers:
                peers[name]["addr"] = addr
                peers[name]["last_seen"] = now

        elif msg_type == "get_directory":
            # Return all registered users and their online status
            directory = {
                n: {"pubkey": i["pubkey"], "online": i["addr"] is not None}
                for n, i in peers.items()
            }
            sock.sendto(json.dumps({"type": "directory", "users": directory}).encode(), addr)

        elif msg_type == "request_mesh":
            # Connect this user to up to 5 random online peers to form the gossip mesh
            name = msg["name"]
            online_addrs = [i["addr"] for n, i in peers.items() if i["addr"] and n != name]
            
            for target_addr in online_addrs[:5]:
                introduce(addr, target_addr)
                introduce(target_addr, addr)