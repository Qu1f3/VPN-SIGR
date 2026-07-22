from pydantic import BaseModel
from datetime import datetime


class StatusResponse(BaseModel):
    """
    Modelo que representa el estado general del servidor VPN.
    """

    server: str
    udp_port: int
    active_clients: int
    ip_pool: str
    cipher: str
    kill_switch: str


class SessionResponse(BaseModel):
    """
    Información pública de una sesión activa.
    """

    client_address: str
    created_at: datetime
    status: str
    authenticated: bool
    virtual_ip: str | None = None


class UserResponse(BaseModel):
    """
    Información pública de un usuario.
    """

    username: str


class UserCreate(BaseModel):
    """
    Modelo para crear un usuario nuevo.
    """

    username: str
    password: str


class KillSwitchStatus(BaseModel):
    """
    Estado actual del Kill Switch.
    """

    enabled: bool
    blocking: bool
    last_change: datetime | None


class MessageResponse(BaseModel):
    """
    Respuesta simple utilizada por la API.
    """

    message: str