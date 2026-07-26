from tunneling.TUN import Adapter


class TunnelServer:

    def __init__(self):
        self.adapter = Adapter()


    def create(self):

        self.adapter.create(
            "VPN-SIGR-SERVER",
            "VPN"
        )

        # /32: evita el problema de ARP cuando hay múltiples clientes
        # remotos sin adaptador propio en esta máquina (ver diagnóstico
        # con pktmon). Necesario en producción, aunque en pruebas locales
        # con un solo cliente en la misma máquina no se notaba.
        self.adapter.set_ip("10.8.0.1")

        # Ruta explícita hacia el pool completo de IPs virtuales de los
        # clientes VPN — sin esto, set_ip con /32 no sabría que el resto
        # del pool debe entregarse por esta interfaz.
        ### self.adapter.add_pool_route("10.8.0.0/24")

        self.adapter.enable_internet_sharing()

        self.adapter.start_session()


        print(
            "TUN del servidor iniciado."
        )


    def write_packet(self, packet):

        self.adapter.write_packet(packet)


    def read_packet(self):

        return self.adapter.read_packet()

    def read_loop(self):
        """Passthrough al read_loop eficiente del Adapter (usa el evento de Windows, no polling)."""
        return self.adapter.read_loop()

    def debug_read_loop(self):

        print("Escuchando paquetes del TUN servidor...")

        # read_loop() usa el evento de Windows en vez de polling — no
        # consume CPU mientras no hay tráfico.
        for packet in self.adapter.read_loop():
            print(
                f"[SERVER TUN READ] paquete recibido: {len(packet)} bytes"
            )


    def close(self):

        self.adapter.close()