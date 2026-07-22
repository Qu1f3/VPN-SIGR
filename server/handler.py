from firewall.killswitch import kill_switch

from protocol.protocol import *
from core.session_manager import (
    authenticate_session,
    create_session,
    get_handshake_transcript,
    get_session,
    get_session_keys,
    remove_session,
    set_handshake_transcript,
    set_session_keys,
    set_virtual_ip,
)
from vpn_crypto.handshake import (
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    verify_auth_tag,
)
from core.ip_manager import assign_ip
from core.users import USERS

from cryptography.exceptions import InvalidTag
from vpn_crypto.cipher import decrypt_packet_payload

def handle_packet(packet, client_address):
    #Procesa los paquetes recibidos por el servidor VPN.
    packet_type = packet.get("type")
    print(f"[HANDLER] Procesando: {packet_type}")

    if packet_type == PacketType.HANDSHAKE:
        return handle_handshake(packet, client_address)

    elif packet_type == PacketType.DATA:
        return handle_data(packet, client_address)
    
    elif packet_type == PacketType.AUTH:
        return handle_auth(packet, client_address)

    elif packet_type == PacketType.DISCONNECT:
        return handle_disconnect(packet, client_address)

    else:
        return create_packet(
            PacketType.ERROR,
            {
                "message": "Tipo de paquete desconocido"
            }
        )

def handle_handshake(packet, client_address):
    
    session_id = create_session(client_address)
    virtual_ip = assign_ip(session_id)

    set_virtual_ip(session_id, virtual_ip)
    
    payload = packet.get(
        "payload",
        {}
    )

    client_public_key_hex = payload.get(
        "client_public_key"
    )

    if not client_public_key_hex:

        return create_packet(
            PacketType.ERROR,
            {
                "message": "Falta client_public_key"
            },
            session_id=session_id
        )

    client_public_key = bytes.fromhex(
        client_public_key_hex
    )

    server_keys = generate_ephemeral_keypair()

    transcript = create_handshake_transcript(
        client_public_key,
        server_keys.public_key_bytes,
    )
    
    set_handshake_transcript(
        session_id,
        transcript,
    )

    session_keys = derive_directional_session_keys(
        server_keys.private_key,
        client_public_key,
        transcript,
        LAB_PSK,
    )

    set_session_keys(
        session_id,
        session_keys,
    )

    server_auth_tag = create_auth_tag(
        LAB_PSK,
        transcript,
        "server",
    )

    print(f"[SESSION] Creada: {session_id}")
    print(f"[SESSION SIZE]: {len(session_id)} bytes")
    print(f"[IP] asignada: {virtual_ip}")

    return create_packet(

        PacketType.HANDSHAKE_ACK,

        {
            "status": Status.OK,
            "message": "Handshake aceptado",
            "virtual_ip": virtual_ip,
            "server_public_key": server_keys.public_key_bytes.hex(),
            "server_auth_tag": server_auth_tag.hex(),
        },

        session_id=session_id 
    )

def handle_data(packet, client_address):

    session_id = packet.get("session_id")
    session = get_session(session_id)

    if not session:

        return create_packet(
            PacketType.ERROR,
            {
                "message": "Sesion invalida"
            }
        )

    if not session["authenticated"]:

        return create_packet(
            PacketType.ERROR,
            {
                "message": "Sesion no autenticada"
            },
            session_id=session_id
        )

    try:
        session_keys = get_session_keys(
            session_id
        )
        
        if not session_keys:

            return create_packet(
                PacketType.ERROR,
                {
                    "message": "Sesion sin claves de cifrado"
                },
                session_id=session_id
            )
            
        plaintext_payload = decrypt_packet_payload(
            packet,
            session_keys.client_to_server_key,
        )

    except InvalidTag:

        return create_packet(
            PacketType.ERROR,
            {
                "message": "DATA invalido: tag AEAD incorrecto"
            },
            session_id=session_id
        )

    print(
        f"[DATA] Datos cifrados recibidos de {client_address}"
    )

    print(
        f"[DATA DESCIFRADO] {plaintext_payload}"
    )

    return create_packet(
        PacketType.DATA_ACK,
        {
            "status": Status.OK
        },
        session_id=session_id
    )

def handle_disconnect(packet, client_address):

    session_id = packet.get("session_id")

    if remove_session(session_id):
        print(f"[SESSION] Eliminada: {session_id}")
    else:
        print(f"[SESSION] No encontrada: {session_id}")

    kill_switch.enable()
    kill_switch.block_traffic()

    print(f"[DISCONNECT] Cliente {client_address}")
    print(f"[SESSION] Eliminada: {session_id}")

    return create_packet(
        PacketType.DISCONNECT,
        {
            "status": Status.OK,
            "message": "Sesion finalizada correctamente."
        },
        session_id=session_id
    )

def handle_auth(packet, client_address):

    session_id = packet.get("session_id")

    session = get_session(session_id)

    if not session:
        return create_packet(
            PacketType.AUTH_FAILED,
            {
                "message": "Sesion invalida"
            }
        )

    payload = packet.get("payload", {})
    username = payload.get("username")
    password = payload.get("password")
    
    client_auth_tag_hex = payload.get(
        "client_auth_tag"
    )

    transcript = get_handshake_transcript(
        session_id
    )

    if not client_auth_tag_hex or not transcript:

        return create_packet(
            PacketType.AUTH_FAILED,
            {
                "message": "Falta autenticacion criptografica del cliente"
            },
            session_id=session_id
        )

    client_auth_tag = bytes.fromhex(
        client_auth_tag_hex
    )

    if not verify_auth_tag(
        LAB_PSK,
        transcript,
        "client",
        client_auth_tag,
    ):

        return create_packet(
            PacketType.AUTH_FAILED,
            {
                "message": "client_auth_tag invalido"
            },
            session_id=session_id
        )

    if USERS.get(username) == password:
        authenticate_session(session_id)

        # La VPN ya está establecida
        kill_switch.allow_traffic()
        kill_switch.disable()

        print(f"[AUTH] Usuario autenticado: {username}")

        return create_packet(
            PacketType.AUTH_SUCCESS,
            {
                "message": "Autenticacion exitosa"
            },
            session_id=session_id
        )

    print(f"[AUTH] Fallo de autenticacion: {username}")

    return create_packet(
        PacketType.AUTH_FAILED,
        {
            "message": "Credenciales invalidas"
        },
        session_id=session_id
    )