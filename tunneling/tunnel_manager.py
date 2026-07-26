from tunneling.TUN import Adapter


server_tun = None


def start_server_tun():

    global server_tun

    server_tun = Adapter()

    server_tun.create(
        "VPN-SIGR"
    )

    server_tun.set_ip(
        "10.8.0.1",
        24
    )

    server_tun.enable_internet_sharing()

    server_tun.start_session()

    print("[TUN] Servidor iniciado")


def get_tun():

    return server_tun