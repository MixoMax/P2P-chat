import socket, json, threading

peers = {}
lock = threading.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 10069))

while True:
    data, addr = sock.recvfrom(1024)
    msg = json.loads(data)

    with lock:
        if msg["type"] == "register":
            name = msg["name"]
            peers[name] = addr  # addr is the *external* IP:port the NAT assigned
            sock.sendto(json.dumps({"status": "registered", "your_addr": list(addr)}).encode(), addr)
            print(f"Registered {name} as {addr}")

        elif msg["type"] == "connect":
            target = msg["target"]
            if target in peers:
                # Tell each peer about the other
                peer_addr = peers[target]
                my_addr = peers[msg["name"]]
                sock.sendto(json.dumps({"peer": list(peer_addr)}).encode(), addr)
                sock.sendto(json.dumps({"peer": list(my_addr)}).encode(), peer_addr)