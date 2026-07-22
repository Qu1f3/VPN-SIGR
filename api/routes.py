from fastapi import APIRouter

from api.models import (
    StatusResponse,
    SessionResponse,
    UserResponse,
    UserCreate,
    KillSwitchStatus,
    MessageResponse
)

from core import session_manager
from core.users import USERS
from fastapi import HTTPException
from core import session_manager
from firewall.killswitch import kill_switch

# Creamos el router que contendrá todos los endpoints de la API
router = APIRouter()


@router.get("/status", response_model=StatusResponse)
def get_status():
    """
    Devuelve el estado actual del servidor VPN.
    """
    sesiones = session_manager.list_sessions()

    return StatusResponse(
        server="running",
        udp_port=51820,
        active_clients=len(sesiones),
        ip_pool="10.8.0.0/24",
        cipher="ChaCha20-Poly1305",
        kill_switch="enabled" if kill_switch.is_enabled() else "disabled"
    )


@router.get("/sessions", response_model=list[SessionResponse])
def get_sessions():
    """
    Devuelve todas las sesiones activas del servidor.
    """

    sesiones = session_manager.list_sessions()

    resultado = []

    for _, sesion in sesiones.items():

        resultado.append(
            SessionResponse(
                client_address=str(sesion["client_address"]),
                created_at=sesion["created_at"],
                status=sesion["status"],
                authenticated=sesion["authenticated"],
                virtual_ip=sesion["virtual_ip"]
            )
        )

    return resultado


@router.get("/users", response_model=list[UserResponse])
def get_users():
    """
    Devuelve la lista de usuarios registrados.
    """

    return [
        UserResponse(username=username)
        for username in USERS.keys()
    ]


@router.post("/users", response_model=UserResponse)
def create_user(user: UserCreate):
    """
    Agrega un nuevo usuario.
    """

    if user.username in USERS:
        raise HTTPException(
            status_code=400,
            detail="El usuario ya existe."
        )

    USERS[user.username] = user.password

    return UserResponse(username=user.username)

@router.delete("/users/{username}")
def delete_user(username: str):
    """
    Elimina un usuario.
    """

    if username not in USERS:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado."
        )

    del USERS[username]

    return {
        "message": f"Usuario '{username}' eliminado correctamente."
    }



@router.get(
    "/killswitch",
    response_model=KillSwitchStatus
)
def get_killswitch():

    estado = kill_switch.status()

    return KillSwitchStatus(
        enabled=estado["enabled"],
        blocking=estado["blocking"],
        last_change=estado["last_change"]
    )


@router.post(
    "/killswitch/enable",
    response_model=MessageResponse
)
def enable_killswitch():

    kill_switch.enable()

    return MessageResponse(
        message="Kill Switch activado correctamente."
    )


@router.post(
    "/killswitch/disable",
    response_model=MessageResponse
)
def disable_killswitch():

    kill_switch.disable()

    return MessageResponse(
        message="Kill Switch desactivado correctamente."
    )


@router.post(
    "/killswitch/block",
    response_model=MessageResponse
)
def block_traffic():

    kill_switch.block_traffic()

    return MessageResponse(
        message="Tráfico bloqueado."
    )


@router.post(
    "/killswitch/allow",
    response_model=MessageResponse
)
def allow_traffic():

    kill_switch.allow_traffic()

    return MessageResponse(
        message="Tráfico permitido."
    )


