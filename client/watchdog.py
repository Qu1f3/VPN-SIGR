"""
Kill Switch automático del lado del CLIENTE.

Corre en un hilo de fondo mientras el túnel está activo. Cada
`check_interval` segundos manda un datagrama de sondeo al servidor VPN
y espera respuesta. No hace falta un paquete de PING/PONG nuevo en el
protocolo: el servidor, en `receive_and_reply` (server/server.py),
responde con un paquete ERROR a cualquier datagrama que no logre
decodificar -- así que un byte cualquiera ya sirve como heartbeat. Si
el servidor está realmente caído o no hay internet, no llega ninguna
respuesta y el socket revienta por timeout.

- Sin respuesta `fail_threshold` veces seguidas -> se asume la VPN
  caída -> se activa el bloqueo real (nadie navega sin protección).
- Vuelve a responder -> se restaura el tráfico automáticamente.
"""
from __future__ import annotations

import socket
import threading

from firewall.killswitch import KillSwitch

# Instancia SEPARADA de la que usa el servidor/API -- esta sí bloquea
# de verdad, porque corre en la máquina del usuario que navega por la VPN.
client_kill_switch = KillSwitch(real_enforcement=True)


class ClientWatchdog:

    def __init__(
        self,
        server_host: str,
        server_port: int,
        check_interval: float = 2.0,
        probe_timeout: float = 1.5,
        fail_threshold: int = 2,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.check_interval = check_interval
        self.probe_timeout = probe_timeout
        self.fail_threshold = fail_threshold

        self._stop_event = threading.Event()
        self._consecutive_failures = 0
        self._thread: threading.Thread | None = None

    def _server_reachable(self) -> bool:
        """
        Manda un byte cualquiera -- no necesita ser un paquete válido
        del protocolo. El servidor va a fallar al decodificarlo y va a
        responder con un ERROR (ver receive_and_reply), pero esa
        respuesta en sí ya es la confirmación de que el proceso sigue
        vivo y alcanzable. No nos importa el CONTENIDO de la
        respuesta, solo que haya llegado alguna antes del timeout.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(self.probe_timeout)
                probe.sendto(b"\x00", (self.server_host, self.server_port))
                probe.recvfrom(2048)
                return True

        except Exception:
            return False

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            reachable = self._server_reachable()

            # Si el usuario desconectó mientras esperábamos la respuesta,
            # salimos sin tocar el firewall.
            if self._stop_event.is_set():
                break

            if reachable:
                self._consecutive_failures = 0

                if client_kill_switch.is_blocking():
                    client_kill_switch.allow_traffic()
                    print("[KillSwitch] Conexión restablecida. Tráfico permitido de nuevo.")

            else:
                self._consecutive_failures += 1

                # Si ya se solicitó detener el watchdog, no bloquear.
                if self._stop_event.is_set():
                    break

                if (
                    self._consecutive_failures >= self.fail_threshold
                    and client_kill_switch.is_enabled()
                    and not client_kill_switch.is_blocking()
                ):
                    client_kill_switch.block_traffic()
                    print(
                        "[KillSwitch] Se perdió la conexión con el servidor VPN "
                        "(o el internet). Bloqueando todo el tráfico saliente."
                    )

            if self._stop_event.wait(self.check_interval):
                break

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        print("[Watchdog] Deteniendo watchdog...")

        self._stop_event.set()

        client_kill_switch.disable()

        if self._thread is not None and self._thread.is_alive():
          self._thread.join(timeout=2)


        self._thread = None

        print("[Watchdog] Watchdog detenido.")