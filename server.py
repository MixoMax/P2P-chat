import socket, json, threading

peers = {}
lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))
print("Rendezvous server listening on :10069")

while True:
    data, addr = sock.recvfrom(1024)
    try:
        msg = json.loads(data)
    except json.JSONDecodeError:
        continue

    with lock:
        if msg["type"] == "register":
            name = msg["name"]
            # Store both public (as seen by server) and private (self-reported)
            peers[name] = {
                "pub":  list(addr),
                "priv": msg.get("priv", list(addr)),
            }
            resp = {"type": "registered", "your_pub": list(addr)}
            sock.sendto(json.dumps(resp).encode(), addr)
            print(f"Registered {name}: pub={addr}, priv={msg.get('priv')}")

        elif msg["type"] == "connect":
            name   = msg["name"]
            target = msg["target"]
            if target not in peers:
                sock.sendto(json.dumps({"type": "error", "msg": "target not found"}).encode(), addr)
                continue
            if name not in peers:
                sock.sendto(json.dumps({"type": "error", "msg": "you are not registered"}).encode(), addr)
                continue

            t = peers[target]
            m = peers[name]
            # Tell each peer about the other (both pub and priv endpoints)
            sock.sendto(json.dumps({"type": "peer", "pub": t["pub"], "priv": t["priv"]}).encode(), addr)
            sock.sendto(json.dumps({"type": "peer", "pub": m["pub"], "priv": m["priv"]}).encode(), tuple(t["pub"]))
            print(f"Introduced {name} <-> {target}")