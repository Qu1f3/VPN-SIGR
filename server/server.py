"""Servidor UDP mínimo para la primera prueba del proyecto.

El servidor recibe texto sin cifrar y responde con un ACK. Esta conducta es
deliberadamente sencilla y será reemplazada por paquetes estructurados cuando
el equipo integre el protocolo.
"""

from __future__ import annotations
from protocol.protocol import *
from server.handler import *

import argparse
import socket
from typing import TypeAlias

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
MAX_DATAGRAM_SIZE = 65535

Address: TypeAlias = tuple[str, int]

def create_server_socket(host: str, port: int) -> socket.socket:
    """Crea un socket UDP y lo enlaza a la IP y al puerto indicados."""

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
    except Exception:
        server_socket.close()
        raise
    return server_socket


def receive_and_reply(server_socket: socket.socket): 
    data, client_address = server_socket.recvfrom(MAX_DATAGRAM_SIZE)

    # Para esta prueba pedagógica esperamos UTF-8. Más adelante el protocolo
    # transportará bytes cifrados y no intentaremos interpretarlos como texto.
    try:
        packet = decode_packet(data)

        print("\nPaquete recibido:")
        print(packet)

        response_packet = handle_packet(packet, client_address)

        response = encode_packet(response_packet)
    
    except Exception as error:

        print("Error:", error)
    
        print(f"Error al decodificar el paquete: {socket.error}")

        response = encode_packet(
            create_packet(
                PacketType.ERROR,
                {
                    "message": "Paquete invalido"
                }
            )
        )

    server_socket.sendto(response, client_address)
    return data, client_address


def run_server(host: str, port: int, once: bool = False) -> None:
    """Escucha datagramas hasta Ctrl+C, o solo uno si ``once`` es verdadero."""

    with create_server_socket(host, port) as server_socket:
        bound_host, bound_port = server_socket.getsockname()
        print(f"Servidor UDP escuchando en {bound_host}:{bound_port}")
        print("Presiona Ctrl+C para detenerlo.")

        while True:
            receive_and_reply(server_socket)
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