from __future__ import annotations
from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from vpn_crypto.cipher import encrypt_packet_payload
from vpn_crypto.handshake import (
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    verify_auth_tag,
)
import argparse
import socket

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
DEFAULT_TIMEOUT_SECONDS = 3.0

client_keys = generate_ephemeral_keypair()

def send_message( host: str, port: int, message: str, timeout: float = DEFAULT_TIMEOUT_SECONDS,) -> str:
    # Paquete de Handshake
    packet = create_packet(PacketType.HANDSHAKE, {"client_public_key": client_keys.public_key_bytes.hex()})
    payload = encode_packet(packet)
    # AF_INET = IPv4, SOCK_DGRAM = UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        # UDP no establece una conexión. Este timeout evita esperar para siempre
        # cuando el servidor está apagado o el puerto está bloqueado.
        client_socket.settimeout(timeout)
        client_socket.sendto(payload, (host, port))
        
        response, server_address = client_socket.recvfrom(65535)

        response_packet = decode_packet(response)
        session_id = response_packet.get("session_id")
        virtual_ip = response_packet["payload"].get("virtual_ip")

        server_public_key_hex = response_packet["payload"].get(
            "server_public_key"
        )

        server_auth_tag_hex = response_packet["payload"].get(
            "server_auth_tag"
        )

        server_public_key = bytes.fromhex(
            server_public_key_hex
        )

        server_auth_tag = bytes.fromhex(
            server_auth_tag_hex
        )

        transcript = create_handshake_transcript(
            client_keys.public_key_bytes,
            server_public_key,
        )

        if not verify_auth_tag(
            LAB_PSK,
            transcript,
            "server",
            server_auth_tag,
        ):

            raise ValueError(
                "No se pudo autenticar el handshake del servidor"
            )

        session_keys = derive_directional_session_keys(
            client_keys.private_key,
            server_public_key,
            transcript,
            LAB_PSK,
        )
        
        client_auth_tag = create_auth_tag(
            LAB_PSK,
            transcript,
            "client",
        )

        print(f"Respuesta de {server_address[0]}:{server_address[1]}:")

        print(response_packet)
        print(f"Session ID: {session_id}")
        print(f"Virtual IP: {virtual_ip}")

    # Paquete de AUTH
        auth_packet = create_packet(
            PacketType.AUTH,
            {
                "username": "admin",
                "password": "1234",
                "client_auth_tag": client_auth_tag.hex()
            },
            session_id=session_id
        )

        client_socket.sendto(
            encode_packet(auth_packet),
            (host, port)
        )

        auth_response, _ = client_socket.recvfrom(65535)

        auth_response_packet = decode_packet(auth_response)

        print("\nRespuesta AUTH: ")
        print(auth_response_packet)

        if auth_response_packet["type"] != PacketType.AUTH_SUCCESS:
            print("Autenticación fallida. No se puede enviar datos.")
            return

    # Paquete de DATA
    #DATA lleva bytes.
    #encrypt_packet_payload() cifra esos bytes.
    #encode_packet() serializa el packet cifrado.
        data_packet = create_packet(
            PacketType.DATA,
            b"Hola desde el tunel VPN cifrado",
            session_id=session_id,
        )
        
        encrypted_data_packet = encrypt_packet_payload(
            data_packet,
            session_keys.client_to_server_key,
        )
        #Por ahora usamos TEMP_DATA_KEY Después lo cambiamos por: client_to_server_key y server_to_client_key
        client_socket.sendto(
            encode_packet(encrypted_data_packet),
            (host, port)
        )

        data_response, _ = client_socket.recvfrom(65535)

        print("\nRespuesta DATA: ")
        print(decode_packet(data_response))

        disconnect_packet = create_packet(
            PacketType.DISCONNECT,
            {},
            session_id=session_id
        )

        client_socket.sendto(
            encode_packet(disconnect_packet),
            (host, port)
        )

        try:
            disconnect_response, _ = client_socket.recvfrom(65535)

            print("\nRespuesta DISCONNECT:")
            print(decode_packet(disconnect_response))

        except socket.timeout:
            print("No se recibió respuesta al DISCONNECT.")

        return response_packet

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente UDP mínimo de la VPN")
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP del servidor")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto UDP")
    parser.add_argument(
        "--message",
        default="hola desde el cliente",
        help="Texto que se enviará sin cifrar en este primer módulo",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Segundos máximos de espera por la respuesta",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    try:
        send_message(args.host, args.port, args.message, args.timeout)
    except socket.timeout:
        raise SystemExit(
            "Tiempo de espera agotado: verifica que el servidor esté encendido, "
            "la IP/puerto sean correctos y el firewall permita UDP."
        )
    except OSError as error:
        raise SystemExit(f"No se pudo usar el socket UDP: {error}") from error

if __name__ == "__main__":
    main()