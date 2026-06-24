import json
import time


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
    session_id: str | None = None
) -> dict:

    return {
        "type": packet_type,
        "session_id": session_id,
        "timestamp": int(time.time()),
        "payload": payload or {}
    }


def encode_packet(packet: dict) -> bytes:

    return json.dumps(packet).encode("utf-8")


def decode_packet(data: bytes) -> dict:

    return json.loads(data.decode("utf-8"))