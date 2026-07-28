import socket as socket_module

from protocol.protocol import (
    PacketType,
    create_packet,
    encode_packet,
    decode_packet,
)

from vpn_crypto.cipher import encrypt_packet_payload, decrypt_packet_payload


def receive_loop(client_socket, session_key, adapter):
    """
    Escucha lo que el servidor reenvía, lo descifra, y lo inyecta al
    TUN propio -- sin esto, el tráfico saliente llega al servidor y
    genera respuesta, pero esa respuesta nunca vuelve al sistema
    operativo del cliente (justo lo que hacía que "se fuera" el
    internet con el túnel completo activado).

    Corre esto en un hilo aparte, en paralelo a TunnelClient.start().
    """
    while True:
        try:
            data, _ = client_socket.recvfrom(65535)
        except socket_module.timeout:
            continue
        except OSError:
            return

        try:
            packet = decode_packet(data)
        except Exception:
            continue

        if packet.get("type") != PacketType.DATA:
            continue

        try:
            plaintext = decrypt_packet_payload(packet, session_key)
        except Exception:
            continue

        adapter.write_packet(plaintext)


class TunnelClient:

    def __init__(
        self,
        adapter,
        socket,
        server_address,
        session_id,
        session_key
    ):

        self.adapter = adapter
        self.socket = socket
        self.server_address = server_address
        self.session_id = session_id
        self.session_key = session_key


    def start(self):

        print("Tunnel client iniciado.")

        # read_loop() espera al evento de Windows en vez de hacer
        # polling — el hilo no consume CPU mientras no hay tráfico.
        for packet in self.adapter.read_loop():

            print(
                f"Paquete capturado del TUN: {len(packet)} bytes"
            )

            vpn_packet = create_packet(
                PacketType.DATA,
                packet,
                session_id=self.session_id
            )

            encrypted_packet = encrypt_packet_payload(
                vpn_packet,
                self.session_key
            )

            self.socket.sendto(
                encode_packet(encrypted_packet),
                self.server_address
            )