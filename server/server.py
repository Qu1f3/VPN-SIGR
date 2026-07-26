from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from server.handler import *
#
from server.tunnel_server import TunnelServer
from server.tunnel_forwarder import TunnelServerForwarder
#

import argparse
import socket
import threading
from typing import TypeAlias

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
MAX_DATAGRAM_SIZE = 65535

Address: TypeAlias = tuple[str, int] ######

def create_server_socket(host: str, port: int) -> socket.socket:
    """Crea un socket UDP y lo enlaza a la IP y al puerto indicados."""

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        server_socket.settimeout(1.0)
    except Exception:
        server_socket.close()
        raise
    return server_socket


def receive_and_reply(server_socket: socket.socket, tunnel: TunnelServer) -> tuple[bytes, Address]: 
    data, client_address = server_socket.recvfrom(MAX_DATAGRAM_SIZE)

    # Para esta prueba pedagógica esperamos UTF-8. Más adelante el protocolo
    # transportará bytes cifrados y no intentaremos interpretarlos como texto.
    try:
        packet = decode_packet(data)

        print("\nPaquete recibido:")
        print(packet)

        response_packet = handle_packet(packet, client_address, tunnel)

        response = encode_packet(response_packet)
    
    except Exception as error:

        print("Error:", error)
    
        print(f"Error al decodificar el paquete: {socket.error}")

        response_packet = create_packet(
            PacketType.ERROR,
            {
                "message": "Paquete invalido"
            }
        )

        response = encode_packet(response_packet)


    print(response_packet)
    server_socket.sendto(response, client_address)
    return data, client_address


def run_server(host: str, port: int, once: bool = False) -> None:
    """Escucha datagramas hasta Ctrl+C, o solo uno si ``once`` es verdadero."""

    tunnel = TunnelServer()
    tunnel.create()

    with create_server_socket(host, port) as server_socket:
        bound_host, bound_port = server_socket.getsockname()

        # El forwarder reenvía tráfico de vuelta al cliente correcto
        # según la IP virtual de destino -- necesario con más de un
        # cliente conectado a la vez. Necesita el socket ya creado,
        # por eso se instancia aquí y no antes.
        forwarder = TunnelServerForwarder(tunnel, server_socket)
        threading.Thread(
            target=forwarder.start,
            daemon=True
        ).start()

        print(f"Servidor UDP escuchando en {bound_host}:{bound_port}")
        print("Presiona Ctrl+C para detenerlo.")

        while True:
            try:
                receive_and_reply(server_socket, tunnel)
            except socket.timeout:
                continue
            if once:
                break


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor UDP mínimo de la VPN")
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP local de escucha")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto UDP")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Termina después de responder el primer datagrama",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        run_server(args.host, args.port, args.once)
    except KeyboardInterrupt:
        print("\nServidor detenido por el usuario.")
    except OSError as error:
        raise SystemExit(
            f"No se pudo escuchar en {args.host}:{args.port}/UDP: {error}"
        ) from error


if __name__ == "__main__":
    main()