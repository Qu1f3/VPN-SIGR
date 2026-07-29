from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import argparse
import getpass
import os
import socket

from client.vpn_client import VPNClient, DEFAULT_TIMEOUT_SECONDS

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cliente de la VPN")
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP del servidor")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Puerto UDP")
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

    client = VPNClient(args.host, args.port, username, password, args.timeout)

    try:
        client.connect()
    except KeyboardInterrupt:
        client.disconnect()
    except socket.timeout:
        raise SystemExit(
            "Tiempo de espera agotado: verifica que el servidor esté encendido, "
            "la IP/puerto sean correctos y el firewall permita UDP."
        )
    except OSError as error:
        raise SystemExit(f"No se pudo usar el socket UDP: {error}") from error


if __name__ == "__main__":
    main()