# core/ip_manager.py
import threading

NETWORK_PREFIX = "10.8.0."
START_IP = 2
MAX_CLIENTS = 250

_lock = threading.Lock()

_assigned_ips = {}    # session_id -> virtual_ip
_ip_to_session = {}   # virtual_ip -> session_id  (índice inverso, evita escaneos O(n))


def assign_ip(session_id):
    with _lock:
        if session_id in _assigned_ips:
            return _assigned_ips[session_id]

        for number in range(START_IP, MAX_CLIENTS + START_IP):
            virtual_ip = NETWORK_PREFIX + str(number)

            if virtual_ip not in _ip_to_session:
                _assigned_ips[session_id] = virtual_ip
                _ip_to_session[virtual_ip] = session_id
                return virtual_ip

        raise Exception("No hay IPs disponibles")


def release_ip(session_id):
    with _lock:
        virtual_ip = _assigned_ips.pop(session_id, None)
        if virtual_ip:
            _ip_to_session.pop(virtual_ip, None)


def get_ip(session_id):
    with _lock:
        return _assigned_ips.get(session_id)


def get_session_by_ip(virtual_ip):
    """Búsqueda inversa (IP virtual -> session_id), O(1)."""
    with _lock:
        return _ip_to_session.get(virtual_ip)


def list_ips():
    with _lock:
        return dict(_assigned_ips)