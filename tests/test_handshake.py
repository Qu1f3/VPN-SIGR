import unittest

from vpn_crypto.handshake import (
    SESSION_KEY_SIZE,
    create_handshake_transcript,
    derive_session_key,
    generate_ephemeral_keypair
)

class X25519HandshakeTest(unittest.TestCase):
    def test_client_and_server_derive_the_same_key(self) -> None:
        client_keys = generate_ephemeral_keypair()
        server_keys = generate_ephemeral_keypair()
        
        transcript = create_handshake_transcript (
            client_keys.public_key_bytes,
            server_keys.public_key_bytes
        )
        
        client_session_key = derive_session_key (
            client_keys.private_key,
            server_keys.public_key_bytes,
            transcript
        )
        
        server_session_key = derive_session_key (
            server_keys.private_key,
            client_keys.public_key_bytes,
            transcript
        )
        
        self.assertEqual( client_session_key, server_session_key )
        self.assertEqual(len( client_session_key ), SESSION_KEY_SIZE)
    
    def test_changing_the_transcript_changes_the_key(self) -> None:
        client_keys = generate_ephemeral_keypair()
        server_keys = generate_ephemeral_keypair()
        
        transcript = create_handshake_transcript(
            client_keys.public_key_bytes,
            server_keys.public_key_bytes
        )
        
        first_key = derive_session_key(
            client_keys.private_key,
            server_keys.public_key_bytes,
            transcript
        )
        
        second_key = derive_session_key(
            client_keys.private_key,
            server_keys.public_key_bytes,
            transcript + b"-altered"
        )
        
        self.assertNotEqual(first_key, second_key)
        
    def test_rejects_an_invalid_public_key_size(self) -> None:
        client_keys = generate_ephemeral_keypair()
        
        with self.assertRaises(ValueError):
            derive_session_key(
                client_keys.private_key,
                b"too-short",
                b"test-transcript"
            )
            
if __name__ == "__main__":
    unittest.main()