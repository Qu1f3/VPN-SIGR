# tunneling/network.py
import subprocess
import time

# En Windows evita que se abra una ventana de consola al llamar netsh.
# getattr con default 0 para que el archivo no falle si se importa/inspecciona
# fuera de Windows.
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _prefix_to_netmask(prefix_length: int) -> str:
    if not (0 <= prefix_length <= 32):
        raise ValueError("prefix_length debe estar entre 0 y 32")

    mask_bits = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    return ".".join(str((mask_bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def set_adapter_ip(
    adapter_name: str,
    ip_address: str,
    prefix_length: int = 24,
    retries: int = 5,
    retry_delay: float = 0.5,
):
    """
    Asigna una IP estática a la interfaz del adaptador usando netsh.
    Requiere permisos de administrador.

    'adapter_name' debe coincidir exactamente con el 'name' que usaste
    en Adapter.create() — es el alias que Windows le pone a la interfaz.

    Justo después de crear el adaptador, Windows puede tardar unos
    milisegundos en registrar la interfaz de red a nivel de sistema.
    Por eso reintenta unas cuantas veces antes de rendirse.
    """
    netmask = _prefix_to_netmask(prefix_length)

    last_error = None

    for attempt in range(1, retries + 1):
        result = subprocess.run(
            [
                "netsh", "interface", "ip", "set", "address",
                f"name={adapter_name}",
                "static",
                ip_address,
                netmask,
            ],
            capture_output=True,
            text=True,
            creationflags=_CREATE_NO_WINDOW,
        )

        if result.returncode == 0:
            return

        last_error = result.stderr.strip() or result.stdout.strip()
        time.sleep(retry_delay)

    raise RuntimeError(
        f"No se pudo asignar la IP al adaptador tras {retries} intentos: {last_error}"
    )


def add_route(destination_prefix: str, interface_name: str, retries: int = 5, retry_delay: float = 0.5):
    """
    Agrega una ruta estática hacia 'destination_prefix' (ej. "10.8.0.0/24")
    a través de la interfaz indicada. Idempotente: si ya existe, no hace nada.

    Necesaria cuando el adaptador tiene su propia IP con máscara /32 (ver
    Adapter.set_ip) — sin esta ruta explícita, Windows no sabría que el
    resto del pool de IPs virtuales debe entregarse por esta interfaz.
    """
    check = _run_powershell(
        f"Get-NetRoute -DestinationPrefix '{destination_prefix}' "
        f"-InterfaceAlias '{interface_name}' -ErrorAction SilentlyContinue"
    )
    if destination_prefix in check.stdout:
        return

    last_error = None
    for attempt in range(retries):
        result = _run_powershell(
            f"New-NetRoute -DestinationPrefix '{destination_prefix}' "
            f"-InterfaceAlias '{interface_name}' -NextHop 0.0.0.0"
        )
        if result.returncode == 0:
            return
        last_error = result.stderr.strip() or result.stdout.strip()
        time.sleep(retry_delay)

    raise RuntimeError(f"No se pudo agregar la ruta '{destination_prefix}': {last_error}")


def network_prefix(ip_address: str, prefix_length: int) -> str:
    """Convierte ej. ("10.8.0.1", 24) -> "10.8.0.0/24" (dirección de red, no de host)."""
    octets = [int(o) for o in ip_address.split(".")]
    ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF
    network_int = ip_int & mask
    network_octets = [(network_int >> shift) & 0xFF for shift in (24, 16, 8, 0)]
    return f"{'.'.join(str(o) for o in network_octets)}/{prefix_length}"


def _run_powershell(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        creationflags=_CREATE_NO_WINDOW,
    )


def enable_forwarding_on_interface(interface_name: str):
    """
    Habilita el reenvío de paquetes IP en la interfaz indicada. Se
    necesita en DOS interfaces para que el NAT funcione: la del TUN
    (por donde entra el tráfico de los clientes VPN) y la de salida a
    internet (ej. "Ethernet"). Sin esto, Windows descarta cualquier
    paquete que no sea "para él mismo" en vez de reenviarlo.
    """
    result = _run_powershell(
        f"Set-NetIPInterface -InterfaceAlias '{interface_name}' -Forwarding Enabled"
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"No se pudo habilitar IP forwarding en '{interface_name}': "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def create_nat(nat_name: str, internal_prefix: str):
    """
    Crea la regla NAT que traduce el tráfico saliente de la subred
    interna (ej. "10.8.0.0/24") hacia la IP pública del servidor.
    Idempotente: si ya existe una regla con ese nombre, no hace nada.
    """
    check = _run_powershell(f"Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue")
    if nat_name in check.stdout:
        return

    result = _run_powershell(
        f"New-NetNat -Name '{nat_name}' -InternalIPInterfaceAddressPrefix '{internal_prefix}'"
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"No se pudo crear la regla NAT '{nat_name}': "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def remove_nat(nat_name: str):
    """Elimina la regla NAT si existe. No falla si ya no existe."""
    _run_powershell(f"Remove-NetNat -Name '{nat_name}' -Confirm:$false -ErrorAction SilentlyContinue")


def get_default_interface_name() -> str:
    """
    Devuelve el nombre de la interfaz que tiene la ruta por defecto
    (0.0.0.0/0) — o sea, la interfaz real de salida a internet. Evita
    tener que adivinar/hardcodear el nombre (ej. "Ethernet" vs
    "Ethernet 2" vs "vEthernet"), lo cual importa especialmente al
    desplegar en un servidor rentado donde no controlas cómo se llama
    la interfaz.
    """
    result = _run_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Sort-Object -Property RouteMetric | "
        "Select-Object -First 1 -ExpandProperty InterfaceAlias)"
    )
    interface_name = result.stdout.strip()

    if result.returncode != 0 or not interface_name:
        raise RuntimeError(
            "No se pudo detectar automáticamente la interfaz de salida a "
            f"internet: {result.stderr.strip() or 'no se encontró ruta por defecto'}"
        )

    return interface_name


def get_default_gateway():
    """
    Devuelve (gateway_ip, interface_alias) de la ruta por defecto
    ACTUAL -- antes de activar el túnel completo. Se necesita para
    poder seguir enrutando el propio tráfico cifrado hacia el servidor
    VPN por la ruta original: sin esto, al activar el túnel completo
    se genera un loop (el tráfico hacia el servidor terminaría
    intentando salir por el túnel que depende de ese mismo tráfico).
    """
    result = _run_powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Sort-Object -Property RouteMetric | "
        "Select-Object -First 1 | "
        "ForEach-Object { \"$($_.NextHop)|$($_.InterfaceAlias)\" }"
    )
    output = result.stdout.strip()

    if result.returncode != 0 or not output or "|" not in output:
        raise RuntimeError("No se pudo detectar la puerta de enlace por defecto actual.")

    gateway_ip, interface_alias = output.split("|", 1)
    return gateway_ip, interface_alias


def pin_route_to_gateway(destination_ip: str, gateway_ip: str, interface_alias: str):
    """
    Fuerza una ruta /32 hacia 'destination_ip' (ej. la IP real del
    servidor VPN) a través de la puerta de enlace/interfaz ORIGINAL.
    Debe llamarse ANTES de enable_full_tunnel() -- evita el loop de
    enrutamiento.
    """
    _run_powershell(
        f"New-NetRoute -DestinationPrefix '{destination_ip}/32' "
        f"-InterfaceAlias '{interface_alias}' -NextHop '{gateway_ip}' "
        f"-RouteMetric 1 -ErrorAction SilentlyContinue"
    )


def remove_route(destination_ip: str):
    _run_powershell(
        f"Remove-NetRoute -DestinationPrefix '{destination_ip}/32' "
        f"-Confirm:$false -ErrorAction SilentlyContinue"
    )


def enable_full_tunnel(tun_interface_alias: str):
    """
    Redirige TODO el tráfico del sistema por el túnel, sin tocar (ni
    entrar en conflicto de métricas con) la ruta por defecto original:
    agrega dos rutas más específicas (0.0.0.0/1 y 128.0.0.0/1) que
    cubren la totalidad del espacio de IPs y ganan por longest-prefix-
    match sobre el 0.0.0.0/0 real -- la misma técnica que usan
    OpenVPN/WireGuard para "redirect-gateway", y evita pelearte con
    métricas de rutas.
    """
    for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
        result = _run_powershell(
            f"New-NetRoute -DestinationPrefix '{prefix}' "
            f"-InterfaceAlias '{tun_interface_alias}' -NextHop 0.0.0.0"
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"No se pudo agregar la ruta de túnel completo '{prefix}': "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )


def disable_full_tunnel(tun_interface_alias: str):
    """Quita las rutas de túnel completo -- restaura el enrutamiento normal."""
    for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
        _run_powershell(
            f"Remove-NetRoute -DestinationPrefix '{prefix}' "
            f"-InterfaceAlias '{tun_interface_alias}' -Confirm:$false -ErrorAction SilentlyContinue"
        )


def set_dns(interface_alias: str, dns_servers: list):
    servers = ",".join(f"'{s}'" for s in dns_servers)
    result = _run_powershell(
        f"Set-DnsClientServerAddress -InterfaceAlias '{interface_alias}' -ServerAddresses ({servers})"
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"No se pudo configurar DNS: {result.stderr.strip() or result.stdout.strip()}"
        )


def reset_dns(interface_alias: str):
    _run_powershell(
        f"Set-DnsClientServerAddress -InterfaceAlias '{interface_alias}' "
        f"-ResetServerAddresses -ErrorAction SilentlyContinue"
    )