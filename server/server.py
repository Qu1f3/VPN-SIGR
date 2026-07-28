from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from server.handler import *
#
from server.tunnel_server import TunnelServer
from server.tunnel_forwarder import TunnelServerForwarder
#
from firewall.monitor import health_monitor

import argparse
import socket
import threading
import traceback
from typing import TypeAlias

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
DEFAULT_API_PORT = 8000
MAX_DATAGRAM_SIZE = 65535


def start_api_in_background(host: str = "0.0.0.0", port: int = DEFAULT_API_PORT) -> None:
    """
    Levanta la API (FastAPI/uvicorn) en un hilo del MISMO proceso que el
    servidor UDP, en vez de correrla como `python -m uvicorn api.api:app`
    en una terminal aparte.

    Esto es lo que soluciona el problema de que la API mostrara un
    estado que no era el real: antes, `server.py` y `api.py` eran dos
    procesos de Python distintos, cada uno con su propia copia en
    memoria de `kill_switch`, `sessions` (session_manager) y `_logs`
    (logger). La API nunca podía ver lo que pasaba en el servidor
    porque literalmente eran objetos distintos en memoria distinta.

    Al importar `api.api.app` aquí y correrlo en un hilo dentro de este
    mismo proceso, la API y el servidor comparten exactamente las
    mismas instancias de esos módulos -- por eso ahora el estado que
    devuelve la API es el estado real y en vivo del servidor.
    """
    import uvicorn
    from api.api import app

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    api_server = uvicorn.Server(config)

    threading.Thread(target=api_server.run, daemon=True).start()
    print(f"API escuchando en http://{host}:{port} (docs en /docs)")

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

        if packet.get("type") != PacketType.PING:
            print("\nPaquete recibido:")
            print(packet)

        response_packet = handle_packet(packet, client_address, tunnel)

        response = encode_packet(response_packet)
    
    except Exception as error:

        print("\n========== ERROR ==========")
        traceback.print_exc()
        print("===========================\n")

        response_packet = create_packet(
            PacketType.ERROR,
            {
                "message": "Paquete invalido"
            }
        )

        response = encode_packet(response_packet)

    if response_packet.get("type") != PacketType.PONG:
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

        # La API corre en un hilo de este mismo proceso: comparte
        # memoria con el servidor, así que su estado siempre es real.
        start_api_in_background()

        # El monitor detecta caídas de internet o del propio servidor
        # y activa/desactiva el Kill Switch automáticamente.
        health_monitor.start()

        while True:
            try:
                receive_and_reply(server_socket, tunnel)
                health_monitor.beat()
            except socket.timeout:
                health_monitor.beat()
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
        health_monitor.stop()
        print("\nServidor detenido por el usuario.")
    except OSError as error:
        raise SystemExit(
            f"No se pudo escuchar en {args.host}:{args.port}/UDP: {error}"
        ) from error


if __name__ == "__main__":
    main()