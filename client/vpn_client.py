"""
Lógica de conexión de la VPN, encapsulada en una clase controlable.

Antes esto vivía directo dentro de client.py como una función que
bloqueaba hasta Ctrl+C -- no servía para una interfaz gráfica, donde
necesitas poder conectar en un hilo de fondo y desconectar bajo
demanda (por un botón), no solo por una señal de teclado.
"""
import socket
import threading

from tunneling.TUN import Adapter
from client.client_tunnel import TunnelClient, receive_loop
from client.watchdog import client_kill_switch, ClientWatchdog

from protocol.protocol import PacketType, create_packet, encode_packet, decode_packet
from vpn_crypto.handshake import (
    LAB_PSK,
    create_auth_tag,
    create_handshake_transcript,
    derive_directional_session_keys,
    generate_ephemeral_keypair,
    verify_auth_tag,
)

DEFAULT_TIMEOUT_SECONDS = 3.0


class VPNClient:
    """
    connect() hace todo el handshake/auth/TUN y luego BLOQUEA hasta
    que algo llame a disconnect() (desde otro hilo) -- por eso está
    pensado para correr connect() en un hilo de fondo.
    """

    def __init__(self, host, port, username, password, timeout=DEFAULT_TIMEOUT_SECONDS, on_status=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.on_status = on_status or (lambda message: None)

        self.client_socket = None
        self.adapter = None
        self.tunnel = None
        self.watchdog = None
        self.connected = False

    def _status(self, message):
        print(message)
        self.on_status(message)

    def connect(self):
        client_keys = generate_ephemeral_keypair()

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.settimeout(self.timeout)

        handshake_packet = create_packet(
            PacketType.HANDSHAKE,
            {"client_public_key": client_keys.public_key_bytes.hex()},
        )
        self.client_socket.sendto(encode_packet(handshake_packet), (self.host, self.port))

        response, _ = self.client_socket.recvfrom(65535)
        response_packet = decode_packet(response)
        session_id = response_packet.get("session_id")
        virtual_ip = response_packet["payload"]["virtual_ip"]
        server_public_key = bytes.fromhex(response_packet["payload"]["server_public_key"])
        server_auth_tag = bytes.fromhex(response_packet["payload"]["server_auth_tag"])

        transcript = create_handshake_transcript(client_keys.public_key_bytes, server_public_key)

        if not verify_auth_tag(LAB_PSK, transcript, "server", server_auth_tag):
            raise ValueError("No se pudo autenticar el handshake del servidor")

        session_keys = derive_directional_session_keys(
            client_keys.private_key, server_public_key, transcript, LAB_PSK,
        )
        client_auth_tag = create_auth_tag(LAB_PSK, transcript, "client")

        self._status(f"Handshake aceptado. IP virtual: {virtual_ip}")

        auth_packet = create_packet(
            PacketType.AUTH,
            {
                "username": self.username,
                "password": self.password,
                "client_auth_tag": client_auth_tag.hex(),
            },
            session_id=session_id,
        )
        self.client_socket.sendto(encode_packet(auth_packet), (self.host, self.port))

        auth_response, _ = self.client_socket.recvfrom(65535)
        auth_response_packet = decode_packet(auth_response)

        if auth_response_packet["type"] != PacketType.AUTH_SUCCESS:
            raise RuntimeError("Autenticación fallida -- revisa usuario/contraseña.")

        self._status("Autenticado. Creando interfaz TUN...")

        self.adapter = Adapter()

        try:
            self.adapter.create(name="VPN-SIGR")
            self.adapter.set_ip(virtual_ip)
            self.adapter.start_session()

            self._status("TUN listo. Activando túnel completo...")

            self.adapter.enable_full_tunnel(self.host, dns_servers=["1.1.1.1", "1.0.0.1"])

            self.tunnel = TunnelClient(
                self.adapter,
                self.client_socket,
                (self.host, self.port),
                session_id,
                session_keys.client_to_server_key,
            )

            threading.Thread(
                target=receive_loop,
                args=(self.client_socket, session_keys.server_to_client_key, self.adapter),
                daemon=True,
            ).start()

            client_kill_switch.configure(
                server_host=self.host,
                server_port=self.port,
                tun_interface="VPN-SIGR",
                client_virtual_ip=virtual_ip,
            )
            self.watchdog = ClientWatchdog(self.host, self.port)

            client_kill_switch.enable()
            self.watchdog.start()

            self.connected = True
            self._status("Conectado — túnel completo activo.")

            # Bloquea aquí hasta que disconnect() cierre el adaptador
            # desde otro hilo (ver comentario en disconnect()).
            self.tunnel.start()

        finally:
            self._status("Cerrando túnel y restaurando red...")
            self.connected = False

            if self.watchdog:
                self.watchdog.stop()

            client_kill_switch.disable()

            if self.adapter:
                self.adapter.close()

            if self.client_socket:
                try:
                    self.client_socket.close()
                except OSError:
                    pass

            self._status("Desconectado.")

    def disconnect(self):
        print("[VPNClient] Iniciando desconexión...")

        if not self.connected:
            return

        self.connected = False

        if self.watchdog:
            print("[VPNClient] Deteniendo watchdog...")
            self.watchdog.stop()
            self.watchdog = None

        if self.adapter:
            print("[VPNClient] Cerrando adaptador...")
            self.adapter.close()

        if self.client_socket:
            print("[VPNClient] Cerrando socket...")
            try:
                self.client_socket.close()
            except OSError:
                pass

        print("[VPNClient] Desconexión finalizada.")
