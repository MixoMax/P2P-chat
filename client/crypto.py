"""
crypto.py — identity keys, ephemeral DH, authenticated encryption.

Key model
---------
  Long-term identity   : Ed25519  (sign / verify)
  Session key exchange : X25519   (ephemeral DH → shared secret)
  Bulk encryption      : ChaCha20-Poly1305 AEAD

Every outgoing packet is:
  1. Serialised to JSON bytes
  2. Encrypted with the current session ChaCha20 key (nonce prepended)
  3. Signed with the sender's Ed25519 private key (signature appended)

Wire format (all binary):
  [4B: payload_len][payload_len B: encrypted payload][64B: Ed25519 signature]

Peers exchange their Ed25519 public keys via the rendezvous server at
registration time.  The server stores them verbatim; recipients verify
signatures themselves — the server is not trusted.
"""

import os, json, pathlib, struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# ── Serialisation helpers ────────────────────────────────────────────────────

def _pub_bytes(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _priv_bytes(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )

# ── Identity key management ──────────────────────────────────────────────────

class Identity:
    """Long-term Ed25519 keypair stored at rest."""

    def __init__(self, keys_dir: str):
        self._dir = pathlib.Path(keys_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        priv_path = self._dir / "ed25519.priv"
        pub_path  = self._dir / "ed25519.pub"

        if priv_path.exists():
            raw = priv_path.read_bytes()
            self._priv = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            self._priv = Ed25519PrivateKey.generate()
            priv_path.write_bytes(_priv_bytes(self._priv))
            priv_path.chmod(0o600)

        self._pub = self._priv.public_key()
        pub_path.write_bytes(_pub_bytes(self._pub))

    @property
    def public_key_bytes(self) -> bytes:
        return _pub_bytes(self._pub)

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    @staticmethod
    def verify(pub_bytes: bytes, data: bytes, sig: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig, data)
            return True
        except (InvalidSignature, Exception):
            return False

# ── Ephemeral session (per connection) ──────────────────────────────────────

class Session:
    """
    One ephemeral X25519 keypair per peer connection.
    Call complete_dh() once you have the peer's ephemeral public key bytes.
    After that, encrypt() / decrypt() are available.
    """

    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        self._pub  = self._priv.public_key()
        self._aead: ChaCha20Poly1305 | None = None

    @property
    def public_key_bytes(self) -> bytes:
        return _pub_bytes(self._pub)

    def complete_dh(self, peer_pub_bytes: bytes):
        """Derive shared ChaCha20 key from peer's ephemeral X25519 public key."""
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared   = self._priv.exchange(peer_pub)
        derived  = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-chat-session-v1",
        ).derive(shared)
        self._aead = ChaCha20Poly1305(derived)

    @property
    def ready(self) -> bool:
        return self._aead is not None

    def encrypt(self, plaintext: bytes) -> bytes:
        """Returns nonce(12B) + ciphertext."""
        nonce = os.urandom(12)
        ct    = self._aead.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, blob: bytes) -> bytes:
        """Inverse of encrypt(); raises on tampered data."""
        nonce, ct = blob[:12], blob[12:]
        return self._aead.decrypt(nonce, ct, None)

# ── Wire framing ─────────────────────────────────────────────────────────────

SIG_LEN = 64  # Ed25519 signature is always 64 bytes

def frame(identity: Identity, session: Session, payload: dict) -> bytes:
    """
    Serialise + encrypt + sign a payload dict.
    If the session isn't ready yet (pre-DH), encrypt is skipped and the raw
    JSON is signed instead — used only for the handshake key-exchange packets.
    """
    raw = json.dumps(payload).encode()
    if session.ready:
        body = session.encrypt(raw)
    else:
        body = raw  # handshake packets go out as plaintext (but still signed)
    sig    = identity.sign(body)
    length = struct.pack(">I", len(body))
    return length + body + sig

def unframe(identity_pub_bytes: bytes | None,
            session: Session | None,
            data: bytes) -> dict | None:
    """
    Verify signature, decrypt, deserialise.
    Returns None on any failure (bad sig, bad crypt, bad JSON).
    Pass identity_pub_bytes=None to skip signature verification (pre-handshake
    bootstrap only — use with caution).
    """
    try:
        if len(data) < 4 + SIG_LEN:
            return None
        length = struct.unpack(">I", data[:4])[0]
        body   = data[4:4 + length]
        sig    = data[4 + length:4 + length + SIG_LEN]

        if identity_pub_bytes is not None:
            if not Identity.verify(identity_pub_bytes, body, sig):
                return None

        if session and session.ready:
            raw = session.decrypt(body)
        else:
            raw = body

        return json.loads(raw)
    except Exception:
        return None

# ── Relay-message encryption ─────────────────────────────────────────────────
# For store-and-forward messages we encrypt to the *recipient's* long-term
# Ed25519 key so relay peers cannot read the content.
# We derive an ephemeral X25519 key from the Ed25519 key via the standard
# Curve25519 co-factor trick (libsodium does this too).
# Python's `cryptography` library doesn't expose that directly, so we instead
# carry a separate long-term X25519 keypair for relay encryption.

class RelayIdentity:
    """Long-term X25519 keypair used only for relay message encryption."""

    def __init__(self, keys_dir: str):
        p = pathlib.Path(keys_dir) / "x25519_relay.priv"
        if p.exists():
            self._priv = X25519PrivateKey.from_private_bytes(p.read_bytes())
        else:
            self._priv = X25519PrivateKey.generate()
            p.write_bytes(_priv_bytes(self._priv))
            p.chmod(0o600)
        self._pub = self._priv.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        return _pub_bytes(self._pub)

    def seal(self, recipient_x25519_pub_bytes: bytes, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext to recipient's long-term X25519 key.
        Returns: ephemeral_pub(32B) + nonce(12B) + ciphertext
        """
        eph_priv = X25519PrivateKey.generate()
        eph_pub  = eph_priv.public_key()
        shared   = eph_priv.exchange(
            X25519PublicKey.from_public_bytes(recipient_x25519_pub_bytes)
        )
        derived  = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"p2p-chat-relay-v1",
        ).derive(shared)
        aead  = ChaCha20Poly1305(derived)
        nonce = os.urandom(12)
        ct    = aead.encrypt(nonce, plaintext, None)
        return _pub_bytes(eph_pub) + nonce + ct

    def open(self, blob: bytes) -> bytes:
        """Decrypt a blob produced by seal()."""
        eph_pub_bytes = blob[:32]
        nonce         = blob[32:44]
        ct            = blob[44:]
        shared = self._priv.exchange(
            X25519PublicKey.from_public_bytes(eph_pub_bytes)
        )
        derived = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=None, info=b"p2p-chat-relay-v1",
        ).derive(shared)
        return ChaCha20Poly1305(derived).decrypt(nonce, ct, None)