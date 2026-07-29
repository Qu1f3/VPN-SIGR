from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

#
from tunneling.TUN import Adapter
from client.client_tunnel import TunnelClient, receive_loop # <--- el ultimo agregado
from client.watchdog import client_kill_switch, ClientWatchdog
#
from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from vpn_crypto.handshake import (
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    verify_auth_tag,
)
import argparse
import getpass
import os
import socket
#
import threading
#

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
DEFAULT_TIMEOUT_SECONDS = 3.0

client_keys = generate_ephemeral_keypair()

def send_message(
    host: str,
    port: int,
    message: str,
    username: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
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
                "username": username,
                "password": password,
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

        print("Creando interfaz TUN...")

        adapter = Adapter()

        try: ########borrar este try en caso de error
            adapter.create(
                name="VPN-SIGR",
            )

            # El cliente solo necesita su propia IP virtual — no maneja un
            # pool de otros peers, así que /32 (default) es correcto aquí.
            adapter.set_ip(virtual_ip)

            adapter.start_session()

            print("TUN listo")

            #########
            adapter.enable_full_tunnel(host, dns_servers=["1.1.1.1", "1.0.0.1"])
            print("Túnel completo activado — todo tu tráfico ahora pasa por la VPN.")
            #########

            tunnel = TunnelClient(
                adapter,
                client_socket,
                (host, port),
                session_id,
                session_keys.client_to_server_key
            )
#################
                # Hilo aparte para las respuestas del servidor -- sin esto,
                # solo funciona la mitad del túnel (salida, no entrada).
            threading.Thread(
                    target=receive_loop,
                    args=(client_socket, session_keys.server_to_client_key, adapter),
                    daemon=True,
            ).start()
    
            tunnel.start()
        finally:
            # SIEMPRE se ejecuta, incluso con Ctrl+C -- sin esto, el
            # usuario se queda sin internet hasta arreglarlo a mano.
            print("Restaurando enrutamiento normal...")
            adapter.close()
#####################

        # A partir de aquí ya hay túnel: activamos el Kill Switch real.
        # configure() le dice al firewall qué NO bloquear (el propio
        # servidor VPN, para poder reconectar, y el tráfico que ya sale
        # por la IP virtual del túnel).
        client_kill_switch.configure(
            server_host=host,
            server_port=port,
            tun_interface="VPN-SIGR",
            client_virtual_ip=virtual_ip,
        )
        watchdog = ClientWatchdog(host, port)

        client_kill_switch.enable()

        watchdog.start()

        try:
            tunnel.start()

        except KeyboardInterrupt:
            pass

        finally:
            print("\nCerrando cliente VPN...")

            watchdog.stop()

            adapter.stop()

            adapter.close()

            client_socket.close()

            client_kill_switch.disable()

            print("Cliente VPN detenido.")

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
    parser.add_argument(
        "--username",
        default=os.environ.get("VPN_USERNAME"),
        help="Usuario (o usa la variable de entorno VPN_USERNAME)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("VPN_PASSWORD"),
        help="Contraseña (o usa VPN_PASSWORD; si se omite, se pide de forma oculta)",
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()

    username = args.username or input("Usuario: ")
    password = args.password or getpass.getpass("Contraseña: ")

    try:
        send_message(args.host, args.port, args.message, username, password, args.timeout)
    except socket.timeout:
        raise SystemExit(
            "Tiempo de espera agotado: verifica que el servidor esté encendido, "
            "la IP/puerto sean correctos y el firewall permita UDP."
        )
    except OSError as error:
        raise SystemExit(f"No se pudo usar el socket UDP: {error}") from error
    finally:
        client_kill_switch.disable()
        
if __name__ == "__main__":
    main()