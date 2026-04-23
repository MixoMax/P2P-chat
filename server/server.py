import socket
import json
import threading
import time

# In-memory store of registered peers.
# Maps: name -> {"name": str, "pub": list, "priv": list, "ed25519": str, "relay_x25519": str}
peers = {}
lock = threading.Lock()

def introduce(name_a, addr_a, info_b, sock, delay=0.0):
    """
    Tell peer A about peer B. 
    A slight delay can be used so both peers have time to arm their UDP receivers for hole punching.
    """
    if delay > 0:
        time.sleep(delay)
        
    payload = json.dumps({
        "type": "peer",
        "name": info_b["name"],
        "pub": info_b["pub"],
        "priv": info_b["priv"],
        "ed25519": info_b["ed25519"],
        "relay_x25519": info_b["relay_x25519"]
    }).encode('utf-8')
    
    try:
        sock.sendto(payload, addr_a)
        print(f"  [INTRO] Sent {info_b['name']}'s info to {name_a} at {addr_a}")
    except Exception as e:
        print(f"  [ERROR] Failed to send intro to {name_a}: {e}")

def main():
    HOST = "0.0.0.0"
    PORT = 10069
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[*] Rendezvous server listening on {HOST}:{PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        except Exception as e:
            print(f"[ERROR] Socket receive error: {e}")
            continue

        with lock:
            msg_type = msg.get("type")

            # 1. Handle Registration (now includes public crypto keys)
            if msg_type == "register":
                name = msg.get("name")
                if not name:
                    continue

                new_peer = {
                    "name": name,
                    "pub": list(addr),
                    "priv": msg.get("priv", list(addr)),
                    "ed25519": msg.get("ed25519", ""),
                    "relay_x25519": msg.get("relay_x25519", "")
                }
                peers[name] = new_peer
                
                reply = json.dumps({
                    "type": "registered", 
                    "your_pub": list(addr)
                }).encode('utf-8')
                
                sock.sendto(reply, addr)
                print(f"[REGISTER] {name} (pub={addr}, priv={new_peer['priv']})")

                # Broadcast peer_online to all other peers
                online_msg = json.dumps({"type": "peer_online", **new_peer}).encode('utf-8')
                for p_name, p_info in peers.items():
                    if p_name != name:
                        try:
                            sock.sendto(online_msg, tuple(p_info["pub"]))
                        except Exception:
                            pass

            # 2. Handle Peer Lookups / Direct Connects
            elif msg_type == "connect":
                name = msg.get("name")
                target = msg.get("target")

                if target not in peers:
                    error = json.dumps({"type": "error", "msg": "target not found"}).encode('utf-8')
                    sock.sendto(error, addr)
                    continue
                if name not in peers:
                    error = json.dumps({"type": "error", "msg": "register first"}).encode('utf-8')
                    sock.sendto(error, addr)
                    continue

                t_info = peers[target]
                m_info = peers[name]
                t_addr = tuple(t_info["pub"])

                print(f"[CONNECT] Coordinating punch between {name} <-> {target}")
                
                # Introduce both sides in background threads so neither blocks the other
                # The requester gets the response instantly (0.0s delay)
                threading.Thread(target=introduce, args=(name, addr, t_info, sock, 0.0), daemon=True).start()
                # The target gets a delayed intro (0.5s) to ensure the requester has already sent the initial punch packets
                threading.Thread(target=introduce, args=(target, t_addr, m_info, sock, 0.5), daemon=True).start()

            # 3. Handle Full Peer List Broadcast (New feature for Relaying/Gossip protocol)
            elif msg_type == "list":
                peer_list =[]
                for p in peers.values():
                    peer_list.append({
                        "name": p["name"],
                        "pub": p["pub"],
                        "priv": p["priv"],
                        "ed25519": p["ed25519"],
                        "relay_x25519": p["relay_x25519"]
                    })
                
                reply = json.dumps({
                    "type": "peer_list",
                    "peers": peer_list
                }).encode('utf-8')
                
                sock.sendto(reply, addr)
                print(f"[LIST] Sent global peer list ({len(peer_list)} peers) to {addr}")

if __name__ == "__main__":
    main()