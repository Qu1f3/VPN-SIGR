import uuid
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

        "virtual_ip": None

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
