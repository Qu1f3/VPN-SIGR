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

from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

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



def create_user(username: str, password: str):
    users = _get_users()

    if username in users:
        raise ValueError("El usuario ya existe.")

    salt_hex, hash_hex = generate_user_entry(password)

    users[username] = {
        "salt": salt_hex,
        "hash": hash_hex
    }

    new_line = f"VPN_USERS_JSON={json.dumps(users)}"

    _write_env_line(str(ENV_FILE), "VPN_USERS_JSON", new_line)

    global _users_cache
    _users_cache = users


def delete_user(username: str):
    users = _get_users()

    if username not in users:
        raise ValueError("El usuario no existe.")

    if username == "admin":
        raise ValueError("No se puede eliminar el usuario administrador.")

    del users[username]

    new_line = f"VPN_USERS_JSON={json.dumps(users)}"

    _write_env_line(str(ENV_FILE), "VPN_USERS_JSON", new_line)

    global _users_cache
    _users_cache = users


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


def _write_env_line(path: str, key: str, full_line: str):
    """
    Reemplaza (o agrega) la línea 'key=...' dentro del archivo .env en
    'path', sin tocar el resto de las líneas. Crea el archivo si no
    existe.
    """
    lines = []
    found = False

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith(f"{key}="):
                    lines.append(full_line + "\n")
                    found = True
                else:
                    lines.append(line)

    if not found:
        lines.append(full_line + "\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)



def get_users():
    """
    Devuelve todos los usuarios cargados desde VPN_USERS_JSON.
    """
    return _get_users()


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    import argparse

    parser = argparse.ArgumentParser(
        description="Genera (y opcionalmente guarda) una entrada de usuario para VPN_USERS_JSON."
    )
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument(
        "--write",
        metavar="ARCHIVO_ENV",
        help=(
            "Escribe/actualiza VPN_USERS_JSON directamente en este archivo "
            "(ej. --write .env) -- útil si no puedes copiar/pegar o escribir "
            "llaves { } en la terminal (ej. teclado de consola de VM)."
        ),
    )
    args = parser.parse_args()

    username, password = args.username, args.password
    salt_hex, hash_hex = generate_user_entry(password)

    existing = {}
    if os.environ.get("VPN_USERS_JSON"):
        existing = json.loads(os.environ["VPN_USERS_JSON"])

    existing[username] = {"salt": salt_hex, "hash": hash_hex}

    new_line = f"VPN_USERS_JSON={json.dumps(existing)}"

    if args.write:
        _write_env_line(args.write, "VPN_USERS_JSON", new_line)
        print(f"Usuario '{username}' guardado en {args.write}. No necesitas copiar/pegar nada más.")
    else:
        print("Agrega esto a tu .env como VPN_USERS_JSON (todo en una linea):")
        print(new_line)