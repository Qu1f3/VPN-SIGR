from protocol.protocol import (
    PacketType,
    create_packet,
    encode_packet
)

from vpn_crypto.cipher import encrypt_packet_payload


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