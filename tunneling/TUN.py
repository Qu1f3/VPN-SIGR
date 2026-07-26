# tunneling/TUN.py
"""
Elige automaticamente la implementacion del Adapter segun el sistema
operativo -- Windows usa Wintun (tun_windows.py), Linux usa
/dev/net/tun (tun_linux.py). El resto del proyecto solo importa
'from tunneling.TUN import Adapter' y nunca necesita saber cual es.
"""
import platform

if platform.system() == "Windows":
    from tunneling.tun_windows import Adapter
else:
    from tunneling.tun_linux import Adapter

__all__ = ["Adapter"]