"""
Monitor de salud para el Kill Switch automático.

Corre en un hilo de fondo DENTRO del mismo proceso que el servidor UDP
y la API. Por eso, cuando este monitor cambia el estado del Kill Switch,
la API lo refleja al instante: ambos comparten la misma instancia de
`kill_switch` en memoria (ya no son dos procesos separados).

Qué vigila, cada `check_interval` segundos:
- Conectividad a internet del servidor (intenta abrir un socket UDP
  hacia un DNS público; no manda tráfico real, solo prueba la ruta).
- Que el ciclo principal del servidor (`server.py`) siga vivo, a través
  de `beat()` -- si el hilo principal se cuelga o el proceso muere,
  `last_heartbeat` deja de actualizarse y el monitor lo detecta como
  caído por timeout.

Qué hace automáticamente:
- Si detecta una caída  -> kill_switch.enable() + block_traffic() + log.
- Si detecta que volvió -> kill_switch.allow_traffic() + disable() + log.

Esto es lo que hace que el Kill Switch sea "automático": nadie tiene que
llamar a los endpoints /killswitch/block o /killswitch/allow a mano.
"""
from __future__ import annotations

import socket
import threading
import time

from core.logger import add_log
from firewall.killswitch import kill_switch


class HealthMonitor:

    def __init__(
        self,
        check_interval: float = 2.0,
        dns_target: tuple[str, int] = ("8.8.8.8", 53),
        heartbeat_timeout: float = 5.0,
        probe_timeout: float = 1.5,
    ):
        self.check_interval = check_interval
        self.dns_target = dns_target
        self.heartbeat_timeout = heartbeat_timeout
        self.probe_timeout = probe_timeout

        self._running = False
        self._thread: threading.Thread | None = None

        self.last_heartbeat = time.monotonic()
        self._was_down = False

    @property
    def is_healthy(self) -> bool:
        """True si, según la última revisión, el servidor tiene internet
        y sigue vivo. Lo usa la API para no reportar "running" a ciegas."""
        return not self._was_down

    def beat(self) -> None:
        """
        El loop principal del servidor debe llamar esto en cada vuelta.
        Es la señal de "sigo vivo" que usa el monitor.
        """
        self.last_heartbeat = time.monotonic()

    def _has_internet(self) -> bool:
        """
        Importante: usamos TCP (SOCK_STREAM), no UDP.
        Un connect() en un socket UDP casi siempre "funciona" aunque no
        haya internet real, porque UDP no hace handshake -- el kernel
        solo verifica que exista una ruta local, no que el destino
        responda. TCP sí hace un handshake real (SYN/SYN-ACK), así que
        de verdad falla cuando no hay conectividad de salida.
        """
        try:
            with socket.create_connection(self.dns_target, timeout=self.probe_timeout):
                pass
            return True
        except OSError:
            return False

    def _loop(self) -> None:
        while self._running:
            server_alive = (time.monotonic() - self.last_heartbeat) < self.heartbeat_timeout
            internet_ok = self._has_internet()
            healthy = server_alive and internet_ok

            if not healthy and not self._was_down:
                kill_switch.enable()
                kill_switch.block_traffic()

                motivo = "sin conexión a internet" if not internet_ok else "el servidor dejó de responder"
                add_log(
                    "WARNING",
                    "KILLSWITCH_AUTO_BLOCK",
                    f"Kill Switch activado automáticamente: {motivo}.",
                )

                self._was_down = True

            elif healthy and self._was_down:
                kill_switch.allow_traffic()
                kill_switch.disable()

                add_log(
                    "INFO",
                    "KILLSWITCH_AUTO_RESTORE",
                    "Conectividad restablecida. Kill Switch desactivado automáticamente.",
                )

                self._was_down = False

            time.sleep(self.check_interval)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.last_heartbeat = time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False


# Instancia global: la importan tanto server.py (para hacer beat() y
# start()) como, si algún día hace falta, cualquier otro módulo del
# mismo proceso que quiera consultar si el monitor está corriendo.
health_monitor = HealthMonitor()
