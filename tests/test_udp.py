"""Prueba minima de ida y vuelta para el flujo UDP estructurado."""

from __future__ import annotations

import threading
import unittest

from client.client import send_message
from protocol.protocol import PacketType
from server.server import create_server_socket, receive_and_reply


def receive_packet_count(server_socket, count: int) -> None:
    for _ in range(count):
        receive_and_reply(server_socket)


class UdpCommunicationTest(unittest.TestCase):
    def test_udp_client_and_server_exchange_structured_packets(self) -> None:
        # El puerto 0 pide al sistema operativo un puerto libre para evitar
        # choques con otros programas o con una instancia manual del servidor.
        with create_server_socket("127.0.0.1", 0) as server_socket:
            _, assigned_port = server_socket.getsockname()
            server_thread = threading.Thread(
                target=receive_packet_count,
                args=(server_socket, 3),
                daemon=True,
            )
            server_thread.start()

            response = send_message(
                host="127.0.0.1",
                port=assigned_port,
                message="prueba UDP",
                timeout=1.0,
            )

            server_thread.join(timeout=1.0)

        self.assertEqual(
            response["type"],
            PacketType.HANDSHAKE_ACK,
        )
        self.assertIn(
            "virtual_ip",
            response["payload"],
        )
        self.assertFalse(server_thread.is_alive())


if __name__ == "__main__":
    unittest.main()