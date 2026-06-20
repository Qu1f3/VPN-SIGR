"""Cliente UDP mínimo para la primera prueba del proyecto.

Todavía no hay handshake, cifrado ni formato de paquetes. El objetivo de este
módulo es comprobar únicamente que un datagrama puede viajar del cliente al
servidor y que la respuesta puede regresar.
"""

from __future__ import annotations

import argparse
import socket


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
DEFAULT_TIMEOUT_SECONDS = 3.0


def send_message( host: str, port: int, message: str, timeout: float = DEFAULT_TIMEOUT_SECONDS,) -> str:
    
    payload = message.encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        # UDP no establece una conexión. Este timeout evita esperar para siempre
        # cuando el servidor está apagado o el puerto está bloqueado.
        client_socket.settimeout(timeout)
        client_socket.sendto(payload, (host, port))
        response, server_address = client_socket.recvfrom(65535)

    decoded_response = response.decode("utf-8")
    print(f"Respuesta de {server_address[0]}:{server_address[1]}: {decoded_response}")
    return decoded_response


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