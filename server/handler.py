from protocol.protocol import *
from core.session_manager import create_session, set_virtual_ip, get_session, authenticate_session
from core.ip_manager import assign_ip
from core.users import USERS



def handle_packet(packet, client_address):
    """
    Procesa los paquetes recibidos por el servidor VPN.
    """

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


    session_id = create_session(
        client_address
    )

    virtual_ip = assign_ip(
        session_id
    )

    set_virtual_ip(
        session_id,
        virtual_ip
    )

    print(
        f"[SESSION] Creada: {session_id}"
    )

    print(
        f"[SESSION SIZE]: {len(session_id)} bytes"
    )

    print(
        f"[IP] asignada: {virtual_ip}"
    )


    return create_packet(

        PacketType.HANDSHAKE_ACK,

        {
            "status": Status.OK,
            "message": "Handshake aceptado",
            "virtual_ip": virtual_ip
        },

        session_id=session_id

        
    )



def handle_data(packet, client_address):

    session_id = packet.get("session_id")
    session = get_session(session_id)

    if not session["authenticated"]:

        return create_packet(
            PacketType.ERROR,
            {
                "message": "Sesion no autenticada"
            }
        )

    print(
        f"[DATA] Datos recibidos de {client_address}"
    )


    print(
        packet.get("payload")
    )


    return create_packet(
        PacketType.DATA_ACK,
        {
            "status": Status.OK
        },
        session_id=session_id
    )



def handle_disconnect(packet, client_address):

    print(
        f"[DISCONNECT] Cliente {client_address}"
    )


    return create_packet(
        PacketType.DISCONNECT,
        {
            "status": Status.OK
        }
    )


def handle_auth(packet, client_address):

    session_id = packet.get(
        "session_id"
    )

    session = get_session(
        session_id
    )

    if not session:

        return create_packet(
            PacketType.AUTH_FAILED,
            {
                "message": "Sesion invalida"
            }
        )

    payload = packet.get(
        "payload",
        {}
    )

    username = payload.get(
        "username"
    )

    password = payload.get(
        "password"
    )

    if USERS.get(username) == password:

        authenticate_session(
            session_id
        )

        print(
            f"[AUTH] Usuario autenticado: {username}"
        )

        return create_packet(
            PacketType.AUTH_SUCCESS,
            {
                "message": "Autenticacion exitosa"
            },
            session_id=session_id
        )

    print(
        f"[AUTH] Fallo de autenticacion: {username}"
    )

    return create_packet(
        PacketType.AUTH_FAILED,
        {
            "message": "Credenciales invalidas"
        },
        session_id=session_id
    )