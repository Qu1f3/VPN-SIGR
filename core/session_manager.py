import secrets
from datetime import datetime

sessions = {}


def create_session(client_address):
    session_id = secrets.token_bytes(16)

    sessions[session_id] = {
        "client_address": client_address,
        "created_at": datetime.now(),
        "status": "CONNECTED",
        "authenticated": False,
        "virtual_ip": None,
        "session_keys": None,
        "handshake_transcript": None,
        "last_receive_sequence": -1,
    }

    return session_id


def get_session(session_id):
    return sessions.get(session_id)


def remove_session(session_id):
    if session_id in sessions:
        del sessions[session_id]
        return True
    return False


def list_sessions():
    return sessions


def set_virtual_ip(session_id, virtual_ip):
    if session_id in sessions:
        sessions[session_id]["virtual_ip"] = virtual_ip
        return True
    return False


def authenticate_session(session_id):
    if session_id in sessions:
        sessions[session_id]["authenticated"] = True
        return True
    return False


def set_session_keys(session_id, session_keys):
    if session_id in sessions:
        sessions[session_id]["session_keys"] = session_keys
        return True
    return False


def get_session_keys(session_id):
    session = get_session(session_id)

    if not session:
        return None

    return session.get("session_keys")


def set_handshake_transcript(session_id, transcript):
    if session_id in sessions:
        sessions[session_id]["handshake_transcript"] = transcript
        return True
    return False


def get_handshake_transcript(session_id):
    session = get_session(session_id)

    if not session:
        return None

    return session.get("handshake_transcript")


def validate_session_sequence(session_id, sequence_number):
    session = get_session(session_id)

    if not session:
        return False

    if sequence_number <= session["last_receive_sequence"]:
        return False

    session["last_receive_sequence"] = sequence_number
    return True