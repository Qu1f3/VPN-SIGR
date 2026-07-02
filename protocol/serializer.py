import json
from protocol.constants import (
    SESSION_ID_SIZE,
    SEQUENCE_NUMBER_SIZE,
    NONCE_SIZE,
    VERSION
)


def serialize_header(packet: dict) -> bytes:

    version = VERSION.to_bytes(
        1,
        byteorder="big"
    )

    packet_type = packet["type"].encode("utf-8")


    if len(packet_type) > 255:
        raise ValueError(
            "Tipo de paquete demasiado grande"
        )


    packet_type_size = len(packet_type).to_bytes(
        1,
        byteorder="big"
    )


    session_id = packet.get("session_id")


    if session_id is None:
        session_id = b"\x00" * SESSION_ID_SIZE


    session_id = serialize_session_id(
        session_id
    )


    sequence_number = serialize_sequence_number(
        packet["sequence_number"]
    )


    nonce = packet["nonce"]


    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Nonce inválido"
        )


    return (
        version +
        packet_type_size +
        packet_type +
        session_id +
        sequence_number +
        nonce
    )


def serialize_session_id(session_id: bytes) -> bytes:

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(
            "session_id debe tener 16 bytes"
        )

    return session_id



def deserialize_session_id(data: bytes) -> bytes:

    if len(data) != SESSION_ID_SIZE:
        raise ValueError(
            "session_id inválido"
        )

    return data



def serialize_sequence_number(
    sequence_number: int
) -> bytes:

    return sequence_number.to_bytes(
        SEQUENCE_NUMBER_SIZE,
        byteorder="big"
    )



def deserialize_sequence_number(
    data: bytes
) -> int:

    if len(data) != SEQUENCE_NUMBER_SIZE:
        raise ValueError(
            "sequence_number inválido"
        )

    return int.from_bytes(
        data,
        byteorder="big"
    )



def generate_nonce(
    sequence_number: int
) -> bytes:

    sequence_bytes = serialize_sequence_number(
        sequence_number
    )

    # 4 bytes reservados + 8 bytes sequence
    nonce = (
        b"\x00" * 4 +
        sequence_bytes
    )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Nonce inválido"
        )

    return nonce

# Convierte el paquete todo junto en bytes

def serialize_packet(packet: dict) -> bytes:

    header = serialize_header(packet)


    payload = packet.get("payload", {})


    if isinstance(payload, bytes):
        payload_bytes = payload

    else:
        payload_bytes = json.dumps(
            payload
        ).encode("utf-8")


    return (
        header +
        payload_bytes
    )


# Convierte el paquete de bytes a json

def deserialize_packet(data: bytes) -> dict:

    index = 0


    # VERSION (1 byte)
    version = data[index]
    index += 1


    # TIPO DE PAQUETE
    packet_type_size = data[index]
    index += 1


    packet_type = data[
        index:index + packet_type_size
    ].decode("utf-8")

    index += packet_type_size


    # SESSION ID (16 bytes)
    session_id = deserialize_session_id(
        data[
            index:index + SESSION_ID_SIZE
        ]
    )

    index += SESSION_ID_SIZE


    # SEQUENCE NUMBER (8 bytes)
    sequence_number = deserialize_sequence_number(
        data[
            index:index + SEQUENCE_NUMBER_SIZE
        ]
    )

    index += SEQUENCE_NUMBER_SIZE


    # NONCE (12 bytes)
    nonce = data[
        index:index + NONCE_SIZE
    ]

    index += NONCE_SIZE


    # Todo lo que queda es payload
    payload_bytes = data[index:]


    if payload_bytes:
        payload = json.loads(
            payload_bytes.decode("utf-8")
        )
    else:
        payload = {}


    return {
        "version": version,
        "type": packet_type,
        "session_id": session_id,
        "sequence_number": sequence_number,
        "nonce": nonce,
        "payload": payload
    }



def get_aad(packet: dict) -> bytes:

    return serialize_header(packet)