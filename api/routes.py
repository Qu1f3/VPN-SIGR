from fastapi import APIRouter, HTTPException

from api.models import (
    StatusResponse,
    SessionResponse,
    UserResponse,
    UserCreate,
    KillSwitchStatus,
    MessageResponse,
    LogResponse
)

from core.users import (
    get_users,
    create_user as create_user_account,
    delete_user as remove_user
)
from core import session_manager
from firewall.killswitch import kill_switch
from firewall.monitor import health_monitor
from core.logger import get_logs

# Creamos el router que contendrá todos los endpoints de la API
router = APIRouter()


@router.get("/status", response_model=StatusResponse)
def get_status():
    """
    Devuelve el estado actual del servidor VPN.
    """
    sesiones = session_manager.list_sessions()

    return StatusResponse(
        server="running" if health_monitor.is_healthy else "degraded",
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
def get_users_endpoint():
    """
    Devuelve la lista de usuarios registrados.
    """

    users = get_users()

    return [
        UserResponse(username=username)
        for username in users.keys()
    ]


@router.post("/users", response_model=UserResponse)
def create_user(user: UserCreate):

    try:

        create_user_account(
            user.username,
            user.password
        )

        return UserResponse(
            username=user.username
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    
@router.delete("/users/{username}", response_model=MessageResponse)
def delete_user(username: str):
    """
    Elimina un usuario.
    """
    try:
        remove_user(username)

        return MessageResponse(
            message="Usuario eliminado correctamente."
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )



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


@router.get(
    "/logs",
    response_model=list[LogResponse]
)
def get_server_logs():
    """
    Devuelve los eventos registrados por el servidor VPN.
    """

    logs = get_logs()

    return [
        LogResponse(
            timestamp=log["timestamp"],
            level=log["level"],
            event=log["event"],
            detail=log["detail"]
        )
        for log in logs
    ]

