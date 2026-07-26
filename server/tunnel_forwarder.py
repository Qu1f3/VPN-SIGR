from protocol.protocol import (
    PacketType,
    create_packet,
    encode_packet
)

from vpn_crypto.cipher import encrypt_packet_payload
from core import ip_manager
from core.session_manager import get_session


def _get_destination_ip(packet: bytes):
    """Lee la IP de destino de un paquete IPv4 crudo. None si no es IPv4 o es inválido."""
    if len(packet) < 20:
        return None
    if (packet[0] >> 4) != 4:
        return None
    return ".".join(str(b) for b in packet[16:20])


class TunnelServerForwarder:
    """
    Lee paquetes que salen del TUN del servidor (trafico de vuelta para
    algun cliente VPN, ya traducido por el NAT) y los reenvia cifrados
    al cliente correcto, usando la IP de destino del paquete para
    encontrar su sesion -- necesario en cuanto hay mas de un cliente
    conectado a la vez.
    """

    def __init__(self, tunnel, socket):
        self.tunnel = tunnel
        self.socket = socket

    def start(self):

        print("Servidor forwarding TUN iniciado")

        # read_loop() espera al evento de Windows en vez de hacer
        # polling -- el hilo no consume CPU mientras no hay trafico.
        for packet in self.tunnel.read_loop():

            destination_ip = _get_destination_ip(packet)

            if destination_ip is None:
                continue

            session_id = ip_manager.get_session_by_ip(destination_ip)

            if session_id is None:
                # El destino no corresponde a ningun cliente VPN conectado.
                continue

            session = get_session(session_id)

            if not session or not session.get("authenticated"):
                continue

            session_keys = session.get("session_keys")

            if not session_keys:
                continue

            print(
                f"[SERVER TUN] paquete generado: {len(packet)} bytes -> {destination_ip}"
            )

            vpn_packet = create_packet(
                PacketType.DATA,
                packet,
                session_id=session_id
            )

            encrypted = encrypt_packet_payload(
                vpn_packet,
                session_keys.server_to_client_key
            )

            self.socket.sendto(
                encode_packet(encrypted),
                session["client_address"]
            )