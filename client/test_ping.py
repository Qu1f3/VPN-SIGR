"""
Prueba de enrutamiento multi-cliente.

Se conecta a la VPN como un cliente normal (handshake + AUTH), y en vez
de esperar tráfico real del sistema operativo, manda directamente un
ping falso hacia 8.8.8.8 usando su propia IP virtual como origen -- el
mismo truco de test_internet.py, pero esta vez pasando por TODO el
camino real: cifrado, sesión, y el forwarder del servidor.

Corre esto en dos terminales a la vez, con --label distinto en cada
una, para confirmar que cada instancia recibe SOLO su propia respuesta
y nunca la de la otra.

Ejemplo:
    python -m client.test_ping --label A
    python -m client.test_ping --label B
"""
from dotenv import load_dotenv
load_dotenv()

import argparse
import getpass
import os
import socket
import threading
import time

from tunneling.TUN import Adapter
from tunneling.packet_utils import build_ipv4_packet, build_icmp_echo_request

from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from vpn_crypto.cipher import encrypt_packet_payload, decrypt_packet_payload
from vpn_crypto.handshake import (
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    verify_auth_tag,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820
TARGET_IP = "8.8.8.8"


def connect(host, port, username, password):
    """Handshake + AUTH. Devuelve (socket, session_id, virtual_ip, session_keys)."""
    client_keys = generate_ephemeral_keypair()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5.0)

    handshake_packet = create_packet(
        PacketType.HANDSHAKE,
        {"client_public_key": client_keys.public_key_bytes.hex()},
    )
    client_socket.sendto(encode_packet(handshake_packet), (host, port))

    response, _ = client_socket.recvfrom(65535)
    response_packet = decode_packet(response)
    session_id = response_packet.get("session_id")
    virtual_ip = response_packet["payload"]["virtual_ip"]
    server_public_key = bytes.fromhex(response_packet["payload"]["server_public_key"])
    server_auth_tag = bytes.fromhex(response_packet["payload"]["server_auth_tag"])

    transcript = create_handshake_transcript(client_keys.public_key_bytes, server_public_key)

    if not verify_auth_tag(LAB_PSK, transcript, "server", server_auth_tag):
        raise ValueError("No se pudo autenticar el handshake del servidor")

    session_keys = derive_directional_session_keys(
        client_keys.private_key, server_public_key, transcript, LAB_PSK,
    )
    client_auth_tag = create_auth_tag(LAB_PSK, transcript, "client")

    auth_packet = create_packet(
        PacketType.AUTH,
        {
            "username": username,
            "password": password,
            "client_auth_tag": client_auth_tag.hex(),
        },
        session_id=session_id,
    )
    client_socket.sendto(encode_packet(auth_packet), (host, port))

    auth_response, _ = client_socket.recvfrom(65535)
    auth_response_packet = decode_packet(auth_response)

    if auth_response_packet["type"] != PacketType.AUTH_SUCCESS:
        raise RuntimeError("Autenticación fallida")

    return client_socket, session_id, virtual_ip, session_keys


def receive_loop(client_socket, session_keys, adapter, label):
    """
    Escucha lo que el servidor reenvía, lo descifra, y lo inyecta al
    TUN propio -- el receptor que faltaba en el cliente.
    """
    while True:
        try:
            data, _ = client_socket.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            return

        packet = decode_packet(data)

        if packet.get("type") != PacketType.DATA:
            continue

        plaintext = decrypt_packet_payload(packet, session_keys.server_to_client_key)

        if len(plaintext) >= 20:
            src = ".".join(str(b) for b in plaintext[12:16])
            dst = ".".join(str(b) for b in plaintext[16:20])
        else:
            src = dst = "?"

        print(f"[{label}] Respuesta recibida: {src} -> {dst} ({len(plaintext)} bytes)")

        adapter.write_packet(plaintext)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--label", default="cliente", help="Nombre para distinguir esta instancia en los logs")
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
    args = parser.parse_args()

    username = args.username or input("Usuario: ")
    password = args.password or getpass.getpass("Contraseña: ")

    client_socket, session_id, virtual_ip, session_keys = connect(args.host, args.port, username, password)

    print(f"[{args.label}] Conectado. IP virtual: {virtual_ip}")

    # Nombre de adaptador único por instancia -- si corres dos a la vez
    # en la misma máquina, no pueden compartir el mismo nombre de TUN.
    adapter = Adapter()
    adapter.create(name=f"VPN-TEST-{args.label}")
    adapter.set_ip(virtual_ip)
    adapter.start_session()

    threading.Thread(
        target=receive_loop,
        args=(client_socket, session_keys, adapter, args.label),
        daemon=True,
    ).start()

    time.sleep(0.5)

    icmp_payload = build_icmp_echo_request(identifier=1, sequence=1)
    raw_packet = build_ipv4_packet(virtual_ip, TARGET_IP, icmp_payload, protocol=1)

    vpn_packet = create_packet(PacketType.DATA, raw_packet, session_id=session_id)
    encrypted = encrypt_packet_payload(vpn_packet, session_keys.client_to_server_key)

    print(f"[{args.label}] Enviando ping falso: {virtual_ip} -> {TARGET_IP}")
    client_socket.sendto(encode_packet(encrypted), (args.host, args.port))

    print(f"[{args.label}] Esperando respuesta (10s)...")
    time.sleep(10)

    adapter.close()
    client_socket.close()


if __name__ == "__main__":
    main()