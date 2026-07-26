from ctypes import *
from pathlib import Path

WINTUN_ADAPTER_HANDLE = c_void_p
WINTUN_SESSION_HANDLE = c_void_p

WINTUN_MIN_RING_CAPACITY = 0x20000 # 128 KiB
WINTUN_MAX_RING_CAPACITY = 0x4000000 # 64 MiB

DLL_PATH = (
    Path(__file__)
    .parent.parent
    / "libs"
    / "wintun.dll"
)


wintun = WinDLL(str(DLL_PATH), use_last_error=True)

# WintunCreateAdapter
wintun.WintunCreateAdapter.argtypes = [
    c_wchar_p,  # adapter name
    c_wchar_p,  # tunnel type
    c_void_p,   # Requested GUID (const GUID*), None si no importa 
]

wintun.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE

# WintunOpenAdapter para reultilizar un adaptador existente
wintun.WintunOpenAdapter.argtypes = [c_wchar_p]
wintun.WintunOpenAdapter.restype = WINTUN_ADAPTER_HANDLE

# WintunCloseAdapter
wintun.WintunCloseAdapter.argtypes = [WINTUN_ADAPTER_HANDLE]
wintun.WintunCloseAdapter.restype = None

# WintunGetAdapterLUID util para asignar IP/rutas al adaptador
wintun.WintunGetAdapterLUID.argtypes = [WINTUN_ADAPTER_HANDLE, c_void_p]
wintun.WintunGetAdapterLUID.restype = None


# WintunStartSession ---
wintun.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, c_uint32]
wintun.WintunStartSession.restype = WINTUN_SESSION_HANDLE
 
# WintunEndSession ---
wintun.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]
wintun.WintunEndSession.restype = None
 
# WintunGetReadWaitEvent (handle de evento para esperar sin busy-loop) ---
wintun.WintunGetReadWaitEvent.argtypes = [WINTUN_SESSION_HANDLE]
wintun.WintunGetReadWaitEvent.restype = c_void_p
 
# WintunReceivePacket ---
wintun.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_uint32)]
wintun.WintunReceivePacket.restype = POINTER(c_uint8)
 
# WintunReleaseReceivePacket ---
wintun.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_uint8)]
wintun.WintunReleaseReceivePacket.restype = None
 
# WintunAllocateSendPacket ---
wintun.WintunAllocateSendPacket.argtypes = [WINTUN_SESSION_HANDLE, c_uint32]
wintun.WintunAllocateSendPacket.restype = POINTER(c_uint8)
 
# WintunSendPacket ---
wintun.WintunSendPacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_uint8)]
wintun.WintunSendPacket.restype = None
 
# WintunGetRunningDriverVersion (útil para diagnóstico) ---
wintun.WintunGetRunningDriverVersion.argtypes = []
wintun.WintunGetRunningDriverVersion.restype = c_uint32
