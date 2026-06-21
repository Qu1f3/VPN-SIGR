import unittest

from vpn_crypto.handshake import(
    SESSION_KEY_SIZE,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    generate_psk
)

class DirectionSessionKeysTest(unittest.TestCase):
    
    def setUp(self) -> None:
        self.client_keys = generate_ephemeral_keypair()
        self.server_keys = generate_ephemeral_keypair()
        self.psk = generate_psk()
        
        self.transcript = create_handshake_transcript(
            self.client_keys.public_key_bytes,
            self.server_keys.public_key_bytes
        )
        
    def derive_as_client(self, psk:bytes):
        return derive_directional_session_keys(
            self.client_keys.private_key,
            self.server_keys.public_key_bytes,
            self.transcript,
            psk
        )
        
    def derive_as_server(self, psk:bytes):
        return derive_directional_session_keys(
            self.server_keys.private_key,
            self.client_keys.public_key_bytes,
            self.transcript,
            psk
        )
        
    def test_client_and_server_derive_equal_keys(self) -> None:
        client_session = self.derive_as_client(self.psk)
        server_session = self.derive_as_server(self.psk)
        
        self.assertEqual(client_session, server_session)
        self.assertEqual(len(client_session.client_to_server_key), SESSION_KEY_SIZE)
        self.assertEqual(len(client_session.server_to_client_key), SESSION_KEY_SIZE)
        
    def test_directions_use_different_keys(self) -> None:
        session_keys = self.derive_as_client(self.psk)
        
        self.assertNotEqual(
            session_keys.client_to_server_key,
            session_keys.server_to_client_key
        )
        
    def test_wrong_psk_produces_different_keys(self) -> None:
        correct_session = self.derive_as_client(self.psk)
        wrong_session = self.derive_as_client(generate_psk())
        
        self.assertNotEqual(correct_session, wrong_session)
        
if __name__ == "__main__":
    unittest.main()