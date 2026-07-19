import unittest

from vpn_crypto.handshake import(
    AUTH_TAG_SIZE,
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    generate_ephemeral_keypair,
    generate_psk,
    verify_auth_tag
)

class PskAuthenticationTest(unittest.TestCase):
    @staticmethod
    
    def create_transcript() -> bytes:
        client_keys = generate_ephemeral_keypair()
        server_keys = generate_ephemeral_keypair()
        
        return create_handshake_transcript(
            client_keys.public_key_bytes,
            server_keys.public_key_bytes
        )
        
        def test_lab_psk_has_valid_size(self) -> None:
            self.assertEqual(len(LAB_PSK), 32)
        
    def test_client_and_server_authentication(self) -> None:
        psk = generate_psk()
        transcript = self.create_transcript()
        
        server_tag = create_auth_tag(psk, transcript, "server")
        client_tag = create_auth_tag(psk, transcript, "client")
        
        self.assertTrue(verify_auth_tag(psk, transcript, "server", server_tag))
        self.assertTrue(verify_auth_tag(psk, transcript, "client", client_tag))
        
        self.assertEqual(len(server_tag), AUTH_TAG_SIZE)
        self.assertEqual(len(client_tag), AUTH_TAG_SIZE)
        
    def test_wrong_psk_is_rejected(self) -> None:
        correct_psk = generate_psk()
        wrong_psk = generate_psk()
        transcript = self.create_transcript()
        
        server_tag = create_auth_tag(correct_psk, transcript, "server")
        
        self.assertFalse(verify_auth_tag(wrong_psk, transcript, "server", server_tag))
    
    def test_modified_transcript_is_rejected(self) -> None:
        psk = generate_psk()
        transcript = self.create_transcript()
        
        server_tag = create_auth_tag(psk, transcript, "server")
        
        self.assertFalse(verify_auth_tag(psk, transcript + b"-modified", "server", server_tag))
        
    def test_server_tag_cannot_authenticate_client(self) -> None:
        psk = generate_psk()
        transcript = self.create_transcript()
        
        server_tag = create_auth_tag(psk, transcript, "server")
        
        self.assertFalse(verify_auth_tag(psk, transcript, "client", server_tag))
        
    def test_short_psk_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_auth_tag(b"short-key", self.create_transcript(), "client")
            
if __name__ == "__main__":
    unittest.main()