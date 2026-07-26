from tunneling.TUN import Adapter

with Adapter() as adapter:
    adapter.create()
    print("Adaptador creado con éxito.")

    adapter.set_ip("10.8.0.1", 24)
    print("IP asignada: 10.8.0.1/24")

    # OJO: cambia "Ethernet" por el nombre real de tu interfaz de salida
    # a internet en este servidor (revísalo con 'Get-NetAdapter' en
    # PowerShell — en VPS suele llamarse "Ethernet" o "Ethernet0").
    # adapter.enable_internet_sharing()
    adapter.enable_forwarding()
    adapter.enable_nat()
    print("NAT e IP forwarding habilitados.")

    adapter.start_session()
    print("Sesión iniciada. Escuchando paquetes (Ctrl+C para salir)...")

    try:
        while True:
            packet = adapter.read_packet()

            if packet:
                print(
                    f"Paquete recibido: {len(packet)} bytes"
                )
    except KeyboardInterrupt:
        print("Cerrando adaptador...")