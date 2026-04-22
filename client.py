import socket, json, threading, time, sys

RENDEZVOUS  = ("188.245.231.101", 10069)
MY_NAME     = sys.argv[1]
TARGET_NAME = sys.argv[2]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))

my_priv_ip   = socket.gethostbyname(socket.gethostname())
my_priv_port = sock.getsockname()[1]

# 1. Register — tell server our private endpoint too
reg = {"type": "register", "name": MY_NAME, "priv": [my_priv_ip, my_priv_port]}
sock.sendto(json.dumps(reg).encode(), RENDEZVOUS)

# Wait for registration ack (ignore anything that isn't our ack)
my_pub = None
while True:
    data, addr = sock.recvfrom(1024)
    msg = json.loads(data)
    if msg.get("type") == "registered":
        my_pub = msg["your_pub"]
        print(f"Registered. Server sees us as {my_pub}")
        break

# 2. Request connection
conn = {"type": "connect", "name": MY_NAME, "target": TARGET_NAME}
sock.sendto(json.dumps(conn).encode(), RENDEZVOUS)

# Wait for peer info
peer_pub  = None
peer_priv = None
while True:
    data, addr = sock.recvfrom(1024)
    msg = json.loads(data)
    if msg.get("type") == "peer":
        peer_pub  = tuple(msg["pub"])
        peer_priv = tuple(msg["priv"])
        break

# 3. Decide which address to use
# If we share the same public IP, we're on the same LAN/host — use private address
if peer_pub[0] == my_pub[0]:
    peer_addr = peer_priv
    print(f"Same public IP detected — using LAN address {peer_addr}")
else:
    peer_addr = peer_pub
    print(f"Punching hole to {peer_addr}")

# 4. Hole punch (still needed even for LAN in some cases)
for _ in range(5):
    sock.sendto(json.dumps({"type": "punch"}).encode(), peer_addr)
    time.sleep(0.1)

# 5. Receiver thread — only print actual chat messages
def receiver():
    while True:
        try:
            data, src = sock.recvfrom(4096)
            msg = json.loads(data)
            if msg.get("type") == "chat":
                print(f"\n[{src[0]}]: {msg['text']}")
                print("> ", end="", flush=True)
            # silently ignore punch and other control frames
        except (socket.timeout, json.JSONDecodeError):
            pass

sock.settimeout(1.0)
threading.Thread(target=receiver, daemon=True).start()

# 6. Keep-alive so NAT mappings don't expire (~10s interval)
def keepalive():
    while True:
        time.sleep(10)
        try:
            sock.sendto(json.dumps({"type": "punch"}).encode(), peer_addr)
        except Exception:
            pass

threading.Thread(target=keepalive, daemon=True).start()

print("Connected! Type messages (Ctrl+C to quit):")
while True:
    try:
        text = input("> ")
        sock.sendto(json.dumps({"type": "chat", "text": text}).encode(), peer_addr)
    except KeyboardInterrupt:
        break