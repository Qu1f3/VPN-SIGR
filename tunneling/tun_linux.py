# tunneling/tun_linux.py
import fcntl
import os
import struct

from tunneling import network_linux as network

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

_TUN_DEVICE = "/dev/net/tun"


class Adapter:
    """
    Interfaz TUN para Linux usando /dev/net/tun -- mismo contrato
    publico que tunneling.tun_windows.Adapter (create, set_ip,
    add_pool_route, enable_internet_sharing, start_session,
    read_packet, read_loop, write_packet, close) para que el resto
    del proyecto (server/, client/, core/) no necesite saber en que
    sistema operativo esta corriendo.
    """

    def __init__(self):
        self.fd = None
        self.name = None
        self.ip_address = None
        self.prefix_length = None
        self.pool_prefix = None

    def create(self, name="VPN-SIGR", tunnel_type=None):
        """'tunnel_type' se ignora -- existe solo por compatibilidad con la firma de Windows."""
        self.fd = os.open(_TUN_DEVICE, os.O_RDWR)

        ifr = struct.pack("16sH", name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        result = fcntl.ioctl(self.fd, TUNSETIFF, ifr)

        # El kernel puede ajustar el nombre pedido -- usamos el que
        # realmente quedo asignado.
        self.name = result[:16].strip(b"\x00").decode()

        network.bring_up(self.name)

        return self.fd

    def set_ip(self, ip_address: str, prefix_length: int = 32):
        """
        Por defecto /32, igual que en Windows y por la misma razon:
        evita que el kernel trate a otros peers del pool como vecinos
        on-link que requieren resolucion ARP. Usa add_pool_route()
        para el resto del rango de IPs de tus clientes.
        """
        if not self.name:
            raise RuntimeError("Primero debes llamar a create().")

        network.set_adapter_ip(self.name, ip_address, prefix_length)
        self.ip_address = ip_address
        self.prefix_length = prefix_length

    def add_pool_route(self, pool_prefix: str):
        if not self.name:
            raise RuntimeError("Primero debes llamar a create().")

        network.add_route(pool_prefix, self.name)
        self.pool_prefix = pool_prefix

    def enable_internet_sharing(
        self,
        wan_interface_name: str = None,
        nat_name: str = None,
        internal_prefix: str = None,
    ):
        """
        'nat_name' se ignora -- existe solo por compatibilidad con la
        firma de Windows (New-NetNat necesita un nombre; iptables no).
        """
        if not self.name or not self.ip_address:
            raise RuntimeError("Primero debes llamar a create() y set_ip().")

        internal_prefix = internal_prefix or self.pool_prefix
        if not internal_prefix:
            raise RuntimeError(
                "No se especifico el rango de IPs virtuales de los "
                "clientes. Pasa 'internal_prefix' o llama primero a "
                "add_pool_route()."
            )

        if wan_interface_name is None:
            wan_interface_name = network.get_default_interface_name()

        network.enable_ip_forwarding()
        network.allow_forwarding(self.name)
        network.create_nat(internal_prefix, wan_interface_name)

    def start_session(self, capacity=None):
        """No-op en Linux -- el fd ya esta listo para leer/escribir. 'capacity' se ignora."""
        if self.fd is None:
            raise RuntimeError("Primero debes llamar a create().")
        return self.fd

    def read_packet(self):
        """Bloquea hasta que haya un paquete disponible."""
        return os.read(self.fd, 65535)

    def read_loop(self, timeout_ms=None):
        """
        Generador que entrega paquetes a medida que llegan.
        'timeout_ms' se ignora -- os.read() ya bloquea de forma
        eficiente (CPU ~0% en reposo) sin necesitar un timeout, a
        diferencia de la version Windows.
        """
        while True:
            packet = os.read(self.fd, 65535)
            if packet:
                yield packet

    def write_packet(self, data: bytes) -> bool:
        os.write(self.fd, data)
        return True

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()