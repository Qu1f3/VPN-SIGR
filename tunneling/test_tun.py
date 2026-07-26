from tunneling.TUN import Adapter

with Adapter() as adapter:
    adapter.create()
    print("Adaptador creado con éxito.")

    adapter.set_ip("10.8.0.1", 24)
    print("IP asignada: 10.8.0.1/24")

    # OJO: cambia "Ethernet" por el nombre real de tu interfaz de salida
    # a internet en este servidor (revísalo con 'Get-NetAdapter' en
    # PowerShell — en VPS suele llamarse "Ethernet" o "Ethernet0").
    adapter.enable_internet_sharing()
    print("NAT e IP forwarding habilitados.")

    adapter.start_session()
    print("Sesión iniciada. Escuchando paquetes (Ctrl+C para salir)...")

    try:
        for packet in adapter.read_loop():
            print(f"Paquete recibido: {len(packet)} bytes")
            # Aquí es donde, en el loop real, cifrarías 'packet' y lo
            # mandarías por tu socket UDP/TCP hacia el peer VPN.
    except KeyboardInterrupt:
        print("Cerrando adaptador...")