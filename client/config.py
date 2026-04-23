"""
config.py — runtime configuration, loaded once at startup.
All tunables live here so nothing is magic-numbered across the codebase.
"""
import json, os, pathlib

DEFAULT = {
    # Rendezvous server
    "rendezvous_host": "188.245.231.101",
    "rendezvous_port": 10069,

    # Relay / store-and-forward
    "relay_cache_limit_mb": 512,          # max MB this peer will store for others
    "relay_ttl_hops":       6,            # max gossip hops before a message is dropped
    "relay_ttl_seconds":    7 * 86400,    # 7 days before a stored message expires
    "relay_rebroadcast_interval": 30,     # seconds between re-gossip sweeps

    # Transport
    "udp_chunk_size":       1200,         # bytes per UDP fragment (safe under 1400 MTU)
    "udp_window_size":      32,           # sliding-window chunks in flight
    "udp_ack_timeout":      1.5,          # seconds before retransmitting a chunk
    "udp_max_retries":      8,
    "keepalive_interval":   5,            # seconds between pings
    "keepalive_dead_after": 20,           # seconds of silence → peer considered dead
    "punch_count":          20,
    "punch_interval":       0.2,

    # Crypto
    "keys_dir": "~/.p2p-chat/keys",      # where Ed25519 + X25519 keys are stored

    # UI
    "theme": "dark",                      # dark | light
}

_cfg = dict(DEFAULT)

def load(path: str | None = None) -> dict:
    global _cfg
    if path and os.path.exists(path):
        with open(path) as f:
            _cfg.update(json.load(f))
    # expand paths
    _cfg["keys_dir"] = str(pathlib.Path(_cfg["keys_dir"]).expanduser())
    return _cfg

def get(key: str):
    return _cfg.get(key, DEFAULT.get(key))