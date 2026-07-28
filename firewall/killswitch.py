from __future__ import annotations

import platform
import subprocess
from datetime import datetime


class KillSwitch:
    """
    Kill Switch de la VPN.

    Con `real_enforcement=False` (comportamiento por defecto): solo
    administra banderas en memoria, como antes. Así lo usan el
    servidor y la API para *reportar* estado, y las pruebas
    automatizadas (`tests/test_killswitch.py`) siguen corriendo sin
    tocar el sistema operativo ni requerir privilegios de administrador.

    Con `real_enforcement=True`: además de las banderas, ejecuta reglas
    reales del firewall del sistema operativo:
      - Windows -> `netsh advfirewall` (interfaz de línea de comandos
        sobre WFP, Windows Filtering Platform).
      - Linux   -> `iptables`, cadena OUTPUT.

    Esta instancia se usa del lado del CLIENTE (ver `client/watchdog.py`),
    no del servidor: cortar el tráfico real tiene que pasar en la
    máquina del usuario que navega a través de la VPN, no en la
    máquina que hospeda el servidor.
    """

    RULE_NAME = "VPN_SIGR_KILLSWITCH"

    def __init__(self, real_enforcement: bool = False):
        self._enabled = False
        self._blocking = False
        self._last_change = None

        self.real_enforcement = real_enforcement

        self._server_host: str | None = None
        self._server_port: int | None = None
        self._tun_interface: str | None = None
        self._client_virtual_ip: str | None = None

    def configure(
        self,
        server_host: str,
        server_port: int,
        tun_interface: str | None = None,
        client_virtual_ip: str | None = None,
    ) -> None:
        """
        Hay que llamar esto ANTES de bloquear de verdad. Sin esto, un
        bloqueo real dejaría al cliente sin forma de volver a hablarle
        al servidor VPN para reconectar -- necesitamos dejar pasar,
        incluso durante el bloqueo:
          - el tráfico hacia el servidor VPN (para reintentar el
            handshake / reconectar),
          - el tráfico que ya sale por el túnel (identificado por la
            IP virtual asignada al cliente, o por la interfaz TUN).
        """
        self._server_host = server_host
        self._server_port = server_port
        self._tun_interface = tun_interface
        self._client_virtual_ip = client_virtual_ip

    def enable(self):
        """Arma el Kill Switch (no bloquea todavía por sí solo)."""
        self._enabled = True
        self._last_change = datetime.now()

    def disable(self):
        """Desarma el Kill Switch. Si estaba bloqueando, primero
        restaura el tráfico -- nunca dejamos reglas de bloqueo puestas
        con el Kill Switch "apagado"."""
        if self._blocking:
            self.allow_traffic()
        self._enabled = False
        self._last_change = datetime.now()

    def block_traffic(self):
        """Bloquea el tráfico. Solo tiene efecto si está habilitado."""
        if not self._enabled:
            return

        if not self._blocking:
            if self.real_enforcement:
                _enforce_block(
                    self._server_host,
                    self._server_port,
                    self._tun_interface,
                    self._client_virtual_ip,
                )
            self._blocking = True

        self._last_change = datetime.now()

    def allow_traffic(self):
        """Restaura el tráfico normal."""
        if self._blocking and self.real_enforcement:
            _enforce_allow()

        self._blocking = False
        self._last_change = datetime.now()

    def is_enabled(self):
        return self._enabled

    def is_blocking(self):
        return self._blocking

    def status(self):
        return {
            "enabled": self._enabled,
            "blocking": self._blocking,
            "last_change": self._last_change,
            "real_enforcement": self.real_enforcement,
        }


# ---------------------------------------------------------------------
# Aplicación real a nivel de sistema operativo
# ---------------------------------------------------------------------

def _run(cmd: list[str]) -> bool:
    """
    Ejecuta un comando del firewall y muestra cualquier error.

    Devuelve True si el comando terminó correctamente y False si falló.
    """

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"\n[KillSwitch] ERROR (código {result.returncode}) ejecutando:")
            print(" ".join(cmd))

            if result.stderr.strip():
                print(result.stderr.strip())
            elif result.stdout.strip():
                print(result.stdout.strip())

            return False

        return True

    except Exception as e:
        print("\n[KillSwitch] Excepción ejecutando comando:")
        print(" ".join(cmd))
        print(e)
        return False

    
def _enforce_block(server_host, server_port, tun_interface, client_virtual_ip):
    system = platform.system()
    if system == "Windows":
        _windows_block(server_host, server_port, client_virtual_ip)
    elif system == "Linux":
        _linux_block(server_host, server_port, tun_interface)
    else:
        print(f"[KillSwitch] Plataforma no soportada para bloqueo real: {system}")


def _enforce_allow():
    system = platform.system()
    if system == "Windows":
        _windows_allow()
    elif system == "Linux":
        _linux_allow()


# --- Windows: netsh advfirewall (WFP) ---------------------------------

def _windows_block(server_host, server_port, client_virtual_ip):
    print("[KillSwitch] Aplicando reglas del firewall...")

    # Limpieza defensiva por si quedaron reglas de una corrida anterior
    # que no se cerró bien (p. ej. el proceso murió sin llamar disable()).
    _windows_allow()

    # 1) Bloquea TODO el tráfico saliente.
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={KillSwitch.RULE_NAME}_BLOCK_OUT",
        "dir=out", "action=block", "enable=yes", "profile=any",
    ])

    # 2) Excepción: permitir hablarle al servidor VPN.
    if server_host and server_port:
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={KillSwitch.RULE_NAME}_ALLOW_SERVER",
            "dir=out", "action=allow",
            f"remoteip={server_host}", "protocol=UDP",
            f"remoteport={server_port}",
        ])

    # 3) Excepción: loopback.
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={KillSwitch.RULE_NAME}_ALLOW_LOOPBACK",
        "dir=out", "action=allow", "remoteip=127.0.0.1",
    ])

    # 4) Excepción: tráfico por el túnel.
    if client_virtual_ip:
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={KillSwitch.RULE_NAME}_ALLOW_TUNNEL",
            "dir=out", "action=allow", f"localip={client_virtual_ip}",
        ])

    print("[KillSwitch] Reglas aplicadas.")


def _windows_allow():
    print("[KillSwitch] Eliminando reglas del firewall...")

    for suffix in ("_BLOCK_OUT", "_ALLOW_SERVER", "_ALLOW_LOOPBACK", "_ALLOW_TUNNEL"):
        _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={KillSwitch.RULE_NAME}{suffix}",
        ])

    print("[KillSwitch] Reglas eliminadas.")


# --- Linux: iptables ----------------------------------------------------

def _linux_block(server_host, server_port, tun_interface):
    _linux_allow()

    _run(["iptables", "-P", "OUTPUT", "DROP"])
    _run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    if server_host and server_port:
        _run([
            "iptables", "-A", "OUTPUT", "-p", "udp",
            "-d", server_host, "--dport", str(server_port),
            "-j", "ACCEPT",
        ])

    if tun_interface:
        _run(["iptables", "-A", "OUTPUT", "-o", tun_interface, "-j", "ACCEPT"])


def _linux_allow():
    _run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    _run(["iptables", "-F", "OUTPUT"])


# ---------------------------------------------------------------------
# Instancia global usada por el SERVIDOR y la API.
#
# A propósito con `real_enforcement=False`: el proceso servidor NO debe
# cortar su propio internet cuando un cliente se desconecta -- eso
# rompería la VPN para todos los demás clientes conectados al mismo
# tiempo, y es el servidor en la nube que acaban de contratar. Aquí el
# Kill Switch solo lleva el estado para mostrarlo en la API/paneles de
# administración.
#
# El bloqueo real ocurre del lado del CLIENTE, con su propia instancia
# (`client_kill_switch` en `client/watchdog.py`) y `real_enforcement=True`.
# ---------------------------------------------------------------------
kill_switch = KillSwitch(real_enforcement=False)
