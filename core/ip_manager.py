# core/ip_manager.py


NETWORK_PREFIX = "10.8.0."

START_IP = 2
MAX_CLIENTS = 250


assigned_ips = {}



def assign_ip(session_id):

    # Si la sesión ya tiene IP
    if session_id in assigned_ips:
        return assigned_ips[session_id]


    # Buscar una IP libre
    for number in range(
        START_IP,
        MAX_CLIENTS + START_IP
    ):

        virtual_ip = NETWORK_PREFIX + str(number)


        if virtual_ip not in assigned_ips.values():

            assigned_ips[session_id] = virtual_ip

            return virtual_ip


    raise Exception(
        "No hay IPs disponibles"
    )



def release_ip(session_id):

    if session_id in assigned_ips:

        del assigned_ips[session_id]



def get_ip(session_id):

    return assigned_ips.get(session_id)



def list_ips():

    return assigned_ips