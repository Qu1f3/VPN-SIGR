import unittest

from core.session_manager import (
    create_session,
    set_handshake_transcript,
)
from protocol.protocol import PacketType
from server.handler import handle_auth


class AuthFlowTest(unittest.TestCase):

    def test_server_rejects_invalid_client_auth_tag(self):
        session_id = create_session(
            ("127.0.0.1", 50010)
        )

        set_handshake_transcript(
            session_id,
            b"fake-transcript",
        )

        auth_packet = {
            "type": PacketType.AUTH,
            "session_id": session_id,
            "payload": {
                "username": "admin",
                "password": "1234",
                "client_auth_tag": (b"\x00" * 32).hex(),
            },
        }

        response_packet = handle_auth(
            auth_packet,
            ("127.0.0.1", 50010),
        )

        self.assertEqual(
            response_packet["type"],
            PacketType.AUTH_FAILED,
        )

        self.assertEqual(
            response_packet["payload"]["message"],
            "client_auth_tag invalido",
        )


if __name__ == "__main__":
    unittest.main()