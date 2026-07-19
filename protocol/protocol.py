import time
from protocol.serializer import generate_nonce, serialize_packet, deserialize_packet
from core.sequence import SequenceManager

sequence_manager = SequenceManager()



class PacketType:

    # Conexión
    HANDSHAKE = "HANDSHAKE"
    HANDSHAKE_ACK = "HANDSHAKE_ACK"

    # Autenticación
    AUTH = "AUTH"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILED = "AUTH_FAILED"

    # Tráfico VPN
    DATA = "DATA"
    DATA_ACK = "DATA_ACK"

    # Control
    PING = "PING"
    PONG = "PONG"

    # Desconexión
    DISCONNECT = "DISCONNECT"

    # Errores
    ERROR = "ERROR"


class Status:
    OK = "OK"
    FAILED = "FAILED"


def create_packet(
    packet_type: str,
    payload: dict | None = None,
    session_id: bytes | None = None
) -> dict:
    
    sequence_number = sequence_manager.next_send()

    nonce = generate_nonce(
        sequence_number
    )

    return {
        "type": packet_type,
        "session_id": session_id,
        "timestamp": int(time.time()),
        "nonce": nonce,
        "sequence_number": sequence_number,
        "payload": payload or {},
        "tag": None
    }



def encode_packet(packet: dict) -> bytes:
    
    return serialize_packet(packet)



def decode_packet(data: bytes) -> dict:

    return deserialize_packet(data)