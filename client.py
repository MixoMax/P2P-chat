import socket, json, threading, time, sys, select

RENDEZVOUS  = ("188.245.231.101", 10069)
MY_NAME     = sys.argv[1]
TARGET_NAME = sys.argv[2]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 0))

my_priv_ip   = socket.gethostbyname(socket.gethostname())
my_priv_port = sock.getsockname()[1]

# 1. Register
reg = {"type": "register", "name": MY_NAME, "priv": [my_priv_ip, my_priv_port]}
sock.sendto(json.dumps(reg).encode(), RENDEZVOUS)

my_pub = None
while True:
    data, addr = sock.recvfrom(1024)
    msg = json.loads(data)
    if msg.get("type") == "registered":
        my_pub = msg["your_pub"]
        print(f"Registered. Server sees us as {my_pub}")
        break

# 2. Request connection
sock.sendto(json.dumps({"type": "connect", "name": MY_NAME, "target": TARGET_NAME}).encode(), RENDEZVOUS)

peer_pub = peer_priv = None
while True:
    data, addr = sock.recvfrom(1024)
    msg = json.loads(data)
    if msg.get("type") == "peer":
        peer_pub  = tuple(msg["pub"])
        peer_priv = tuple(msg["priv"])
        break

# 3. Pick address
if peer_pub[0] == my_pub[0]:
    peer_addr = peer_priv
    print(f"Same public IP — using LAN address {peer_addr}")
else:
    peer_addr = peer_pub
    print(f"Punching hole to {peer_addr}")

# 4. Hole punch — send more punches over a longer window
#    so the NAT mapping is definitely open before the other side sends
print("Punching...", end=" ", flush=True)
for _ in range(10):
    sock.sendto(json.dumps({"type": "punch"}).encode(), peer_addr)
    time.sleep(0.2)
print("done.")

# 5. Receiver thread — writes above the current input line
import os
is_windows = os.name == 'nt'

print_lock = threading.Lock()

def receiver():
    sock.settimeout(1.0)
    while True:
        try:
            data, src = sock.recvfrom(4096)
            msg = json.loads(data)
            if msg.get("type") == "chat":
                with print_lock:
                    if is_windows:
                        # Overwrite the "> " prompt line cleanly
                        sys.stdout.write(f"\r\033[K[{src[0]}]: {msg['text']}\n> ")
                    else:
                        sys.stdout.write(f"\r\033[K[{src[0]}]: {msg['text']}\n> ")
                    sys.stdout.flush()
        except socket.timeout:
            pass
        except json.JSONDecodeError:
            pass

threading.Thread(target=receiver, daemon=True).start()

# 6. Keep-alive
def keepalive():
    while True:
        time.sleep(10)
        try:
            sock.sendto(json.dumps({"type": "punch"}).encode(), peer_addr)
        except Exception:
            pass

threading.Thread(target=keepalive, daemon=True).start()

# 7. Input loop — use a simple blocking input, receiver prints above it
print("Connected! Type messages (Ctrl+C to quit):")
while True:
    try:
        sys.stdout.write("> ")
        sys.stdout.flush()
        text = sys.stdin.readline().rstrip("\n")
        if text:
            sock.sendto(json.dumps({"type": "chat", "text": text}).encode(), peer_addr)
    except KeyboardInterrupt:
        print("\nBye.")
        break