from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

X25519_KEY_SIZE = 32
SESSION_KEY_SIZE = 32
HKDF_INFO = b"academic-vpn-v1/x25519-session-key"

@dataclass(frozen=True, slots=True)
class EphemeralKeyPair:
    private_key: X25519PrivateKey
    public_key_bytes: bytes
    
def generate_ephemeral_keypair() -> EphemeralKeyPair:
    private_key = X25519PrivateKey.generate()
    
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    
    return EphemeralKeyPair(
        private_key=private_key,
        public_key_bytes=public_key_bytes
    )
    
def create_handshake_transcript( client_public_key: bytes, server_public_key: bytes ) -> bytes:
    
    if len(client_public_key) != X25519_KEY_SIZE:
        raise ValueError("La clave pública del cliente debe medir 32 bytes")
    
    if len(server_public_key) != X25519_KEY_SIZE:
        raise ValueError("La clave pública del servidor debe medir 32 bytes")
    
    return (
    b"client-public-key:" + client_public_key + b"|server-public-key:" + server_public_key
)
    
def derive_session_key( own_private_key: X25519PrivateKey, peer_public_key_bytes: bytes, transcript: bytes ) -> bytes:
    
    if len(peer_public_key_bytes) != X25519_KEY_SIZE:
        raise ValueError("La clave pública remota debe medir 32 bytes")
    
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    
    shared_secret = own_private_key.exchange(peer_public_key)
    
    transcript_hasher = hashes.Hash(hashes.SHA256())
    transcript_hasher.update(transcript)
    transcript_hash = transcript_hasher.finalize()
    
    key_derivation = HKDF(
        algorithm = hashes.SHA256(),
        length = SESSION_KEY_SIZE,
        salt = transcript_hash,
        info = HKDF_INFO
    )
    
    return key_derivation.derive(shared_secret)