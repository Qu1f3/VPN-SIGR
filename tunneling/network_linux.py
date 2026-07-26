# tunneling/network_linux.py
import subprocess


def _run(cmd, allow_exists=False):
    """
    Corre un comando. Si allow_exists=True, ignora el error típico de
    "ya existe" (idempotencia) — útil para poder llamar create()/set_ip()
    varias veces sin que truene si el servidor se reinicia.
    """
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if allow_exists and "File exists" in stderr:
            return result
        raise RuntimeError(f"Comando falló: {' '.join(cmd)}\n{stderr}")

    return result


def bring_up(interface_name: str):
    """Activa la interfaz (equivalente a que Windows la muestre como 'conectada')."""
    _run(["ip", "link", "set", "dev", interface_name, "up"])


def set_adapter_ip(interface_name: str, ip_address: str, prefix_length: int = 32):
    """Asigna una IP a la interfaz. Idempotente: si ya la tiene, no falla."""
    _run(
        ["ip", "addr", "add", f"{ip_address}/{prefix_length}", "dev", interface_name],
        allow_exists=True,
    )


def add_route(destination_prefix: str, interface_name: str):
    """
    Agrega una ruta hacia destination_prefix (ej. "10.8.0.0/24") a
    través de la interfaz. Idempotente.
    """
    _run(
        ["ip", "route", "add", destination_prefix, "dev", interface_name],
        allow_exists=True,
    )


def enable_ip_forwarding():
    """Equivalente a Set-NetIPInterface -Forwarding Enabled, pero a nivel de todo el kernel."""
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])


def _iptables_rule_exists(table: str, rule_args: list) -> bool:
    check = subprocess.run(
        ["iptables", "-t", table, "-C"] + rule_args,
        capture_output=True,
        text=True,
    )
    return check.returncode == 0


def _add_iptables_rule(table: str, rule_args: list):
    """Agrega una regla solo si no existe ya (idempotente)."""
    if _iptables_rule_exists(table, rule_args):
        return

    result = subprocess.run(
        ["iptables", "-t", table, "-A"] + rule_args,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(f"No se pudo agregar la regla iptables: {result.stderr.strip()}")


def create_nat(internal_prefix: str, wan_interface_name: str):
    """
    Equivalente a New-NetNat: traduce el tráfico saliente del pool
    interno (ej. "10.8.0.0/24") a la IP pública del servidor.
    """
    _add_iptables_rule(
        "nat",
        ["POSTROUTING", "-s", internal_prefix, "-o", wan_interface_name, "-j", "MASQUERADE"],
    )


def allow_forwarding(interface_name: str):
    """
    Reglas de FORWARD explícitas para el TUN. En muchas distros la
    política por defecto de la cadena FORWARD es DROP, así que sin
    esto el NAT queda configurado pero el kernel igual descarta el
    tráfico antes de llegar a él.
    """
    _add_iptables_rule("filter", ["FORWARD", "-i", interface_name, "-j", "ACCEPT"])
    _add_iptables_rule("filter", ["FORWARD", "-o", interface_name, "-j", "ACCEPT"])


def get_default_interface_name() -> str:
    """
    Devuelve el nombre de la interfaz con la ruta por defecto
    (0.0.0.0/0) -- la interfaz real de salida a internet. Evita
    hardcodear "eth0" (en distintos proveedores cloud puede llamarse
    distinto: eth0, ens5, enp0s3, etc.).
    """
    result = _run(["ip", "route", "show", "default"])
    output = result.stdout.strip()

    if not output:
        raise RuntimeError(
            "No se pudo detectar la interfaz de salida a internet "
            "(no hay ruta por defecto)."
        )

    # Formato típico: "default via 172.31.0.1 dev eth0 proto dhcp metric 100"
    parts = output.split()

    if "dev" in parts:
        return parts[parts.index("dev") + 1]

    raise RuntimeError(f"No se pudo interpretar la ruta por defecto: {output}")