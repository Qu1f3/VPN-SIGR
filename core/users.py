# core/users.py
"""
Credenciales de usuario cargadas desde la variable de entorno
VPN_USERS_JSON -- nunca hardcodeadas en el codigo, y nunca en texto
plano (se guarda solo el hash + salt de cada password).

Para generar una entrada nueva:
    python -m core.users <username> <password>

Eso imprime el JSON que debes agregar a tu .env en VPN_USERS_JSON.
"""
import hashlib
import hmac
import json
import os
import secrets

_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )


def _load_users_from_env():
    raw = os.environ.get("VPN_USERS_JSON")

    if not raw:
        raise RuntimeError(
            "Falta la variable de entorno VPN_USERS_JSON. Corre "
            "'python -m core.users <username> <password>' para generar una "
            "entrada y agregarla a tu .env (ver .env.example)."
        )

    return json.loads(raw)


_users_cache = None


def _get_users():
    global _users_cache
    if _users_cache is None:
        _users_cache = _load_users_from_env()
    return _users_cache


def verify_credentials(username: str, password: str) -> bool:
    """Reemplaza al viejo 'USERS.get(username) == password'."""
    users = _get_users()
    entry = users.get(username)

    if not entry:
        return False

    salt = bytes.fromhex(entry["salt"])
    expected_hash = bytes.fromhex(entry["hash"])
    actual_hash = _hash_password(password, salt)

    # compare_digest evita timing attacks (comparar con == filtra
    # informacion sobre en que byte difieren dos strings).
    return hmac.compare_digest(actual_hash, expected_hash)


def generate_user_entry(password: str):
    """Genera (salt_hex, hash_hex) listos para guardar en VPN_USERS_JSON."""
    salt = secrets.token_bytes(16)
    hashed = _hash_password(password, salt)
    return salt.hex(), hashed.hex()


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    import sys

    if len(sys.argv) != 3:
        print("Uso: python -m core.users <username> <password>")
        sys.exit(1)

    username, password = sys.argv[1], sys.argv[2]
    salt_hex, hash_hex = generate_user_entry(password)

    existing = {}
    if os.environ.get("VPN_USERS_JSON"):
        existing = json.loads(os.environ["VPN_USERS_JSON"])

    existing[username] = {"salt": salt_hex, "hash": hash_hex}

    print("Agrega esto a tu .env como VPN_USERS_JSON (todo en una linea):")
    print(json.dumps(existing))