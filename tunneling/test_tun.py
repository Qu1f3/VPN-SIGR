from tunneling.TUN import Adapter

with Adapter() as adapter:
    adapter.create()
    print("Adaptador creado con éxito.")

    # /32 por defecto -- evita que otras IPs del pool se traten como
    # vecinos on-link que requieren resolución ARP (ver docstring de
    # set_ip en tun_linux.py / tun_windows.py).
    adapter.set_ip("10.8.0.1")
    print("IP asignada: 10.8.0.1/32")

    adapter.add_pool_route("10.8.0.0/24")
    print("Ruta al pool agregada: 10.8.0.0/24")

    # Sin argumento, detecta sola la interfaz de salida a internet
    # (equivalente a lo que hacías pasando "enp0s3" a mano).
    adapter.enable_internet_sharing()
    print("NAT e IP forwarding habilitados.")

    adapter.start_session()
    print("Sesión iniciada. Escuchando paquetes (Ctrl+C para salir)...")

    try:
        for packet in adapter.read_loop():
            print(f"Paquete recibido: {len(packet)} bytes")
    except KeyboardInterrupt:
        print("Cerrando adaptador...")