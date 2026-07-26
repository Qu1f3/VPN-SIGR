import time

from tunneling.TUN import Adapter
from tunneling.packet_utils import build_ipv4_packet, build_icmp_echo_request

FAKE_CLIENT_IP = "10.8.0.5"   # simula un cliente conectado a la VPN (no es la IP del propio TUN)
TARGET_IP = "8.8.8.8"         # DNS público de Google, solo para la prueba

with Adapter() as adapter:
    adapter.create()
    print("Adaptador creado.")

    adapter.set_ip("10.8.0.1", 24)
    print("IP asignada: 10.8.0.1/24")

    adapter.enable_internet_sharing()
    print("NAT e IP forwarding habilitados.")

    adapter.start_session()
    print("Sesión iniciada.\n")

    icmp_payload = build_icmp_echo_request(identifier=1, sequence=1)
    packet = build_ipv4_packet(FAKE_CLIENT_IP, TARGET_IP, icmp_payload, protocol=1)

    print(f"Inyectando ICMP echo request: {FAKE_CLIENT_IP} -> {TARGET_IP}")
    adapter.write_packet(packet)

    print("Esperando respuesta (hasta 10s)...\n")
    deadline = time.monotonic() + 10
    success = False

    for received in adapter.read_loop(timeout_ms=1000):
        if time.monotonic() > deadline:
            break

        if received is None:
            continue  # timeout parcial de 1s, seguimos esperando hasta 'deadline'

        if len(received) < 21:
            continue

        src = ".".join(str(b) for b in received[12:16])
        dst = ".".join(str(b) for b in received[16:20])
        protocol = received[9]

        if src == TARGET_IP and dst == FAKE_CLIENT_IP and protocol == 1 and received[20] == 0:
            print(f"✅ Respuesta ICMP recibida de {src}. ¡El NAT + forwarding funcionan!")
            success = True
            break

        print(f"(ignorando paquete {src} -> {dst}, protocolo {protocol})")

    if not success:
        print(
            "❌ No llegó respuesta a tiempo. Posibles causas:\n"
            "   - El firewall de Windows está bloqueando ICMP saliente/entrante.\n"
            "   - Si esto corre en un VPS: el proveedor filtra tráfico por IP de "
            "origen no reconocida (revisa 'source/destination check' o "
            "'IP forwarding' en el panel del proveedor).\n"
            "   - El NAT no quedó bien configurado (revisa 'Get-NetNat' en PowerShell)."
        )