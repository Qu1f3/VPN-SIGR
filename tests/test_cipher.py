import secrets
import unittest

from cryptography.exceptions import InvalidTag

from core.session_manager import (
    authenticate_session,
    create_session,
    set_session_keys,
)
from protocol.serializer import (
    deserialize_packet,
    generate_nonce,
    serialize_packet,
)
from server.handler import handle_data
from vpn_crypto.cipher import (
    TEMP_DATA_KEY,
    decrypt_packet_payload,
    decrypt_payload,
    encrypt_packet_payload,
    encrypt_payload,
)
from vpn_crypto.handshake import (
    DirectionalSessionKeys,
    SESSION_KEY_SIZE,
)


class CipherTest(unittest.TestCase):

    def test_temp_data_key_has_valid_size(self):
        self.assertEqual(
            len(TEMP_DATA_KEY),
            SESSION_KEY_SIZE,
        )

    def test_encrypt_and_decrypt_payload(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)
        nonce = generate_nonce(1)
        plaintext = b"Cristiano Ronaldo"
        aad = b"header-autenticado"

        encrypted_payload = encrypt_payload(
            key,
            nonce,
            plaintext,
            aad,
        )

        decrypted_payload = decrypt_payload(
            key,
            nonce,
            encrypted_payload,
            aad,
        )

        self.assertEqual(
            decrypted_payload,
            plaintext,
        )

        self.assertNotEqual(
            encrypted_payload,
            plaintext,
        )

    def test_modified_ciphertext_is_rejected(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)
        nonce = generate_nonce(2)
        plaintext = b"Kylian Mbappe"
        aad = b"header-autenticado"

        encrypted_payload = encrypt_payload(
            key,
            nonce,
            plaintext,
            aad,
        )

        modified_payload = bytearray(
            encrypted_payload
        )

        modified_payload[0] ^= 1

        with self.assertRaises(InvalidTag):
            decrypt_payload(
                key,
                nonce,
                bytes(modified_payload),
                aad,
            )

    def test_modified_aad_is_rejected(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)
        nonce = generate_nonce(3)
        plaintext = b"mensaje secreto"
        aad = b"header-autenticado"

        encrypted_payload = encrypt_payload(
            key,
            nonce,
            plaintext,
            aad,
        )

        with self.assertRaises(InvalidTag):
            decrypt_payload(
                key,
                nonce,
                encrypted_payload,
                b"header-alterado",
            )

    def test_encrypt_and_decrypt_packet_payload(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)

        packet = {
            "type": "DATA",
            "session_id": b"\x01" * 16,
            "sequence_number": 10,
            "nonce": generate_nonce(10),
            "payload": b"paquete-ip-simulado",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            key,
        )

        decrypted_payload = decrypt_packet_payload(
            encrypted_packet,
            key,
        )

        self.assertEqual(
            decrypted_payload,
            packet["payload"],
        )

        self.assertNotEqual(
            encrypted_packet["payload"],
            packet["payload"],
        )

        self.assertEqual(
            len(encrypted_packet["tag"]),
            16,
        )

    def test_modified_packet_header_is_rejected(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)

        packet = {
            "type": "DATA",
            "session_id": b"\x01" * 16,
            "sequence_number": 11,
            "nonce": generate_nonce(11),
            "payload": b"paquete-ip-simulado",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            key,
        )

        encrypted_packet["type"] = "PING"

        with self.assertRaises(InvalidTag):
            decrypt_packet_payload(
                encrypted_packet,
                key,
            )

    def test_serialized_encrypted_packet_keeps_payload_as_bytes(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)

        packet = {
            "type": "DATA",
            "session_id": b"\x01" * 16,
            "sequence_number": 12,
            "nonce": generate_nonce(12),
            "payload": b"paquete-ip-simulado",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            key,
        )

        encoded_packet = serialize_packet(
            encrypted_packet,
        )

        decoded_packet = deserialize_packet(
            encoded_packet,
        )

        self.assertIsInstance(
            decoded_packet["payload"],
            bytes,
        )

        decrypted_payload = decrypt_packet_payload(
            decoded_packet,
            key,
        )

        self.assertEqual(
            decrypted_payload,
            packet["payload"],
        )

    def test_server_rejects_data_when_header_is_modified(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)
        session_id = create_session(
            ("127.0.0.1", 50000)
        )

        authenticate_session(
            session_id
        )

        set_session_keys(
            session_id,
            DirectionalSessionKeys(
                client_to_server_key=key,
                server_to_client_key=secrets.token_bytes(SESSION_KEY_SIZE),
            ),
        )

        packet = {
            "type": "DATA",
            "session_id": session_id,
            "sequence_number": 20,
            "nonce": generate_nonce(20),
            "payload": b"payload protegido",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            key,
        )

        encrypted_packet["type"] = "PING"

        response_packet = handle_data(
            encrypted_packet,
            ("127.0.0.1", 50000),
        )

        self.assertEqual(
            response_packet["type"],
            "ERROR",
        )

        self.assertIn(
            "tag AEAD",
            response_packet["payload"]["message"],
        )

    def test_server_rejects_data_when_ciphertext_is_modified(self):
        key = secrets.token_bytes(SESSION_KEY_SIZE)
        session_id = create_session(
            ("127.0.0.1", 50001)
        )

        authenticate_session(
            session_id
        )

        set_session_keys(
            session_id,
            DirectionalSessionKeys(
                client_to_server_key=key,
                server_to_client_key=secrets.token_bytes(SESSION_KEY_SIZE),
            ),
        )

        packet = {
            "type": "DATA",
            "session_id": session_id,
            "sequence_number": 21,
            "nonce": generate_nonce(21),
            "payload": b"payload protegido",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            key,
        )

        modified_payload = bytearray(
            encrypted_packet["payload"]
        )

        modified_payload[0] ^= 1

        encrypted_packet["payload"] = bytes(
            modified_payload
        )

        response_packet = handle_data(
            encrypted_packet,
            ("127.0.0.1", 50001),
        )

        self.assertEqual(
            response_packet["type"],
            "ERROR",
        )

        self.assertIn(
            "tag AEAD",
            response_packet["payload"]["message"],
        )

    def test_data_decryption_fails_with_wrong_key(self):
        good_key = b"\x11" * SESSION_KEY_SIZE
        wrong_key = b"\x22" * SESSION_KEY_SIZE

        packet = {
            "type": "DATA",
            "session_id": b"\x01" * 16,
            "sequence_number": 30,
            "nonce": generate_nonce(30),
            "payload": b"payload protegido",
            "tag": None,
        }

        encrypted_packet = encrypt_packet_payload(
            packet,
            good_key,
        )

        with self.assertRaises(InvalidTag):
            decrypt_packet_payload(
                encrypted_packet,
                wrong_key,
            )


if __name__ == "__main__":
    unittest.main()