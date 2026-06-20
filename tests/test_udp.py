"""Prueba mínima de ida y vuelta para el módulo UDP."""

from __future__ import annotations

import threading
import unittest

from client.client import send_message
from server.server import create_server_socket, receive_and_reply


class UdpCommunicationTest(unittest.TestCase):
    def test_udp_client_and_server_exchange_a_message(self) -> None:
        # El puerto 0 pide al sistema operativo un puerto libre para evitar
        # choques con otros programas o con una instancia manual del servidor.
        with create_server_socket("127.0.0.1", 0) as server_socket:
            _, assigned_port = server_socket.getsockname()
            server_thread = threading.Thread(
                target=receive_and_reply,
                args=(server_socket,),
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

        self.assertEqual(response, "ACK: prueba UDP")
        self.assertFalse(server_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
