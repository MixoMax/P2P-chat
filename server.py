import socket, json, threading, time

peers = {}
lock  = threading.Lock()
sock  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))
print("Rendezvous server listening on :10069")

def introduce(name_a, addr_a, name_b, info_b):
    """Tell A about B after a short delay so both have time to arm their receivers."""
    time.sleep(0.5)
    payload = json.dumps({"type": "peer", "pub": info_b["pub"], "priv": info_b["priv"]}).encode()
    sock.sendto(payload, addr_a)
    print(f"  Sent {name_b} info to {name_a} at {addr_a}")

while True:
    data, addr = sock.recvfrom(1024)
    try:
        msg = json.loads(data)
    except json.JSONDecodeError:
        continue

    with lock:
        if msg["type"] == "register":
            name = msg["name"]
            peers[name] = {"pub": list(addr), "priv": msg.get("priv", list(addr))}
            sock.sendto(json.dumps({"type": "registered", "your_pub": list(addr)}).encode(), addr)
            print(f"Registered {name}: pub={addr}, priv={msg.get('priv')}")

        elif msg["type"] == "connect":
            name   = msg["name"]
            target = msg["target"]

            if target not in peers:
                sock.sendto(json.dumps({"type": "error", "msg": "target not found"}).encode(), addr)
                continue
            if name not in peers:
                sock.sendto(json.dumps({"type": "error", "msg": "register first"}).encode(), addr)
                continue

            t_info = peers[target]
            m_info = peers[name]
            t_addr = tuple(t_info["pub"])

            print(f"Introducing {name} <-> {target}")
            # Introduce both sides simultaneously in threads so neither waits on the other
            threading.Thread(target=introduce, args=(name,  addr,   target, t_info), daemon=True).start()
            threading.Thread(target=introduce, args=(target, t_addr, name,  m_info), daemon=True).start()