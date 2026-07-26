# tunneling/sync.py
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102


def wait(handle, timeout_ms=INFINITE) -> bool:
    """
    Bloquea el hilo (sin consumir CPU) hasta que 'handle' se active o
    pase 'timeout_ms'. Devuelve True si se activó, False si fue timeout.
    """
    result = kernel32.WaitForSingleObject(handle, timeout_ms)

    if result == WAIT_OBJECT_0:
        return True
    if result == WAIT_TIMEOUT:
        return False

    raise RuntimeError(
        f"WaitForSingleObject falló: {ctypes.WinError(ctypes.get_last_error())}"
    )