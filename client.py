import socket, json, threading, time, sys

RENDEZVOUS = ("p2pct.linush.org", 10069)
MY_NAME = sys.argv[1]      # e.g. "alice"
TARGET  = sys.argv[2]      # e.g. "bob"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))  # OS picks a local port

# 1. Register with rendezvous — this also reveals our external IP:port to the server
sock.sendto(json.dumps({"type": "register", "name": MY_NAME}).encode(), RENDEZVOUS)
resp = json.loads(sock.recv(1024))
print(f"Registered. Server sees us as {resp['your_addr']}")

# 2. Ask to connect to target
sock.sendto(json.dumps({"type": "connect", "name": MY_NAME, "target": TARGET}).encode(), RENDEZVOUS)
resp = json.loads(sock.recv(1024))
peer_addr = tuple(resp["peer"])
print(f"Punching hole to {peer_addr}")

# 3. Simultaneous hole punch — send a few punches, peer does the same
for _ in range(5):
    sock.sendto(b"punch", peer_addr)
    time.sleep(0.1)

# 4. Now just communicate directly
sock.settimeout(1.0)

def receiver():
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if data != b"punch":
                print(f"\n[{addr[0]}]: {data.decode()}")
        except socket.timeout:
            pass

threading.Thread(target=receiver, daemon=True).start()

print("Connected! Type messages:")
while True:
    msg = input()
    sock.sendto(msg.encode(), peer_addr)