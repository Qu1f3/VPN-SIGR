from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from protocol.constants import AEAD_TAG_SIZE, NONCE_SIZE
from vpn_crypto.handshake import SESSION_KEY_SIZE
from protocol.serializer import get_aad

# Solo para pruebas locales de cifrado DATA.
# Luego se reemplazara por claves derivadas del handshake X25519 + PSK/HMAC.
TEMP_DATA_KEY = b"\x11" * SESSION_KEY_SIZE

def validate_key(key: bytes) -> None: #Asegura que la calve mida 32 bytes, el cipher lo requiere
    if not isinstance(key, bytes):
        raise TypeError("La clvae AEAD debe ser bytes")
    
    if len(key) != SESSION_KEY_SIZE:
        raise ValueError("La clave AEAD debe medir 32 bytes")
    
def validate_nonce(nonce: bytes) -> None: #Asegura que el nonce mida 12 bytes
    if not isinstance(nonce, bytes):
        raise TypeError("El nonce debe ser bytes")
    
    if len(nonce) != NONCE_SIZE:
        raise ValueError("El nonce debe medir 12 bytes")
    
def encrypt_payload(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    #Cifra el texto y lo devuelve ciphertext + AEAD tag de 16 bytes
    validate_key(key)
    validate_nonce(nonce)
    
    if not isinstance(plaintext, bytes):
        raise TypeError("El plaintext debe ser bytes")
    
    if not isinstance(aad, bytes):
        raise TypeError("El AAD debe ser bytes")
    
    cipher = ChaCha20Poly1305(key)
    
    return cipher.encrypt(nonce, plaintext, aad)
    
    
    
def decrypt_payload(key: bytes, nonce: bytes, encrypted_payload: bytes, aad: bytes) -> bytes:
    #Verifica el tag AEAD y devuelve el plaintext, si el ciphertext, nonce o AAD fueron alterados, falla.
    validate_key(key)
    validate_nonce(nonce)
    
    if not isinstance(encrypted_payload, bytes):
        raise TypeError("El payload cifrado debe ser bytes")
    
    if len(encrypted_payload) < AEAD_TAG_SIZE:
        raise ValueError("El payload cifrado no contiene tag AEAD")
    
    if not isinstance(aad, bytes):
        raise TypeError("El AAD debe ser bytes")
    
    cipher = ChaCha20Poly1305(key)
    
    return cipher.decrypt(nonce, encrypted_payload, aad)

def encrypt_packet_payload(packet: dict, key: bytes) -> dict:
    #Toma el payload en bytes, cifra usando nonce + AAD, devuelve una copia del packet
    #con payload cifrado y guarda el tag como referencia en packet["tag"]
    plaintext = packet["payload"]
    
    if not isinstance(plaintext, bytes):
        raise TypeError("El payload del packet debe ser bytes antes de cifrar")
    
    aad = get_aad(packet) #Serializa el header
    
    encrypted_payload = encrypt_payload(key, packet["nonce"], plaintext, aad)
    encrypted_packet = packet.copy()
    encrypted_packet["payload"] = encrypted_payload
    encrypted_packet["tag"] = encrypted_payload[-AEAD_TAG_SIZE:]
    
    return encrypted_packet

def decrypt_packet_payload(packet: dict, key: bytes) -> bytes:
    #Toma el payload cifrado, vuelve a contruir el mismo AAD desde el header
    #y si nada fue alternado, devuelve el payload original
    encrypted_payload = packet["payload"]
    aad = get_aad(packet)
    
    return decrypt_payload(key, packet["nonce"], encrypted_payload, aad)