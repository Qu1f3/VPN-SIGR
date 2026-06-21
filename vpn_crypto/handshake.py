from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import secrets
from cryptography.exceptions import InvalidSignature

X25519_KEY_SIZE = 32
SESSION_KEY_SIZE = 32
HKDF_INFO = b"academic-vpn-v1/x25519-session-key"

PSK_SIZE = 32
AUTH_TAG_SIZE = 32
_AUTH_LABELS = {
    "client": b"academic-vpn-v1/client-authentication",
    "server": b"academic-vpn-v1/server-authentication"
}

DIRECTIONAL_KEY_MATERIAL_SIZE = SESSION_KEY_SIZE * 2
DIRECTIONAL_HKDF_INFO = (b"academic-vpn-v1/directional-session-keys")

@dataclass(frozen=True, slots=True)
class EphemeralKeyPair:
    private_key: X25519PrivateKey
    public_key_bytes: bytes
    
@dataclass(frozen=True, slots=True)
class DirectionalSessionKeys:
    client_to_server_key: bytes
    server_to_client_key: bytes
    
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

def generate_psk() -> bytes:
    return secrets.token_bytes(PSK_SIZE)

def _build_authenticator(psk: bytes, transcript: bytes, role: str) -> hmac.HMAC:
    
    if not isinstance(psk, bytes):
        raise TypeError("La PSK debe ser de tipo bytes")
    
    if len(psk) != PSK_SIZE:
        raise ValueError("La PSK debe medir exactamente 32 bytes")
    
    if not isinstance(transcript, bytes) or not transcript:
        raise ValueError("El transcript debe contener bytes")
    
    if role not in _AUTH_LABELS:
        raise ValueError("El rol debe ser 'client' o 'server'")
    
    authenticator = hmac.HMAC(psk, hashes.SHA256())
    
    authenticator.update(_AUTH_LABELS[role])
    authenticator.update(len(transcript).to_bytes(4, "big"))
    authenticator.update(transcript)
    
    return authenticator

def create_auth_tag(psk: bytes, transcript: bytes, role:str) -> bytes:
    authenticator = _build_authenticator(psk, transcript, role)
    return authenticator.finalize()

def verify_auth_tag(psk: bytes, transcript: bytes, role:str, received_tag: bytes) -> bool:
    if not isinstance(received_tag, bytes):
        return False
    
    if len(received_tag) != AUTH_TAG_SIZE:
        return False
    
    authenticator = _build_authenticator(psk, transcript, role)
    
    try:
        authenticator.verify(received_tag)
    except InvalidSignature:
        return False
    
    return True

def derive_directional_session_keys(
    own_private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
    transcript: bytes,
    psk: bytes
    ) -> DirectionalSessionKeys:
    
    if len(peer_public_key_bytes) != X25519_KEY_SIZE:
        raise ValueError("La clave pública remota debe medir 32 bytes")
    
    if not isinstance(transcript, bytes) or not transcript:
        raise ValueError("El transcript debe contener bytes")
    
    if not isinstance(psk, bytes):
        raise ValueError("La PSK debe ser de tipo bytes")
    
    if len(psk) != PSK_SIZE:
        raise ValueError("La PSK debe medir exactamente 32 bytes")
    
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = own_private_key.exchange(peer_public_key)
    
    transcript_hasher = hashes.Hash(hashes.SHA256())
    transcript_hasher.update(transcript)
    transcript_hash = transcript_hasher.finalize()
    
    key_derivation = HKDF(
        algorithm=hashes.SHA256(),
        length=DIRECTIONAL_KEY_MATERIAL_SIZE,
        salt=transcript_hash,
        info = DIRECTIONAL_HKDF_INFO
    )
    
    key_material = key_derivation.derive(shared_secret + psk)
    
    return DirectionalSessionKeys(
        client_to_server_key=key_material[:SESSION_KEY_SIZE],
        server_to_client_key=key_material[SESSION_KEY_SIZE:]
    )