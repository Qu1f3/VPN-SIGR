# VPN-SIGR — Resumen de avances y guía para probar

## Qué se hizo

### 1. Interfaz TUN (`tunneling/`)
- `wintun.py` — bindings completos a la DLL de Wintun (crear/cerrar adaptador, sesión, leer/escribir paquetes).
- `TUN.py` — clase `Adapter` con: `create()`, `set_ip()`, `add_pool_route()`, `enable_internet_sharing()`, `start_session()`, `read_loop()` (eficiente, sin polling), `write_packet()`, `close()`.
- `network.py` — configuración de IP, NAT, y forwarding en Windows vía PowerShell/netsh (detecta sola la interfaz de salida a internet).
- `sync.py` — espera eficiente por eventos de Windows (evita que el proceso consuma CPU en reposo).
- **Detalle importante:** el adaptador usa `/32` (una sola IP) más una ruta explícita al pool (`add_pool_route`), en vez de `/24` directo — esto evita un problema real de resolución ARP que documentamos a fondo (Wintun no responde ARP, así que una subred ancha en la IP del adaptador hace que el tráfico a otros peers se pierda en silencio).

### 2. Servidor (`server/`)
- `tunnel_server.py` — levanta el TUN del servidor con la config correcta (`/32` + pool route + NAT).
- `tunnel_forwarder.py` — **pieza nueva clave**: lee el TUN del servidor, identifica a qué cliente pertenece cada paquete de vuelta (por IP virtual, vía `core/ip_manager.py`), y lo reenvía cifrado solo a ese cliente. Sin esto, con más de un cliente conectado el tráfico de respuesta no sabía a quién mandarse.
- `handler.py` — se eliminó una duplicación (`handle_data` escribía cada paquete dos veces al TUN).
- `server.py` — conecta el forwarder como hilo de fondo.

### 3. Cliente (`client/`)
- `client.py` / `client_tunnel.py` — ya no dependen de `polling` manual, usan `read_loop()`. Se limpió código muerto que nunca se ejecutaba.
- `test_ping.py` — script de diagnóstico: se conecta como cliente real, manda un ping simulado hacia `8.8.8.8` a través de todo el cifrado/sesión, y confirma que la respuesta vuelve solo a él. Útil para probar el enrutamiento sin depender de que el sistema operativo ya tenga la ruta configurada hacia el TUN.

### 4. Credenciales (`core/users.py`)
- Ya no hay usuarios/contraseñas en el código. Se generan con `python -m core.users <usuario> <password>` y se guardan **hasheadas** (PBKDF2 + salt) en la variable de entorno `VPN_USERS_JSON`.
- `.env` se carga automático con `python-dotenv` — ya no hace falta exportar variables a mano.

## Qué queda pendiente (a propósito, fuera de este alcance)
- El paquete `AUTH` viaja sin cifrar por la red (la contraseña, aunque ya no está hardcodeada, no va protegida en tránsito).
- `validate_session_sequence` existe en `session_manager.py` pero no se usa — no hay protección contra replay todavía.
- `LAB_PSK` sigue definido en el código (no se tocó, fuera del alcance actual).

## Cómo probarlo (para el equipo)

### Requisitos
- Windows (Wintun es específico de Windows).
- Python 3.11+.
- Correr todo **como administrador** (Wintun y los cambios de red lo exigen).
- `pip install python-dotenv` (y las demás dependencias del proyecto).
- Tener `wintun.dll` en la carpeta `libs/` en la raíz del proyecto.

### Configuración inicial (una sola vez por persona)
1. Copiar `.env.example` como `.env` en la raíz del proyecto.
2. Generar un usuario:
   ```
   python -m core.users admin "una-password-cualquiera"
   ```
3. Pegar el resultado en `VPN_USERS_JSON` dentro de `.env`.
4. (Opcional) Poner `VPN_USERNAME` y `VPN_PASSWORD` en `.env` para no tener que escribirlos cada vez.

### Prueba básica (un cliente)
Terminal 1 (como administrador):
```
python -m server.server
```
Terminal 2 (como administrador):
```
python -m client.client
```
Debe verse el handshake, la autenticación, y tráfico DATA fluyendo en ambas terminales.

### Prueba multi-cliente (recomendada)
Con el servidor corriendo, abrir 2-3 terminales más y correr, casi al mismo tiempo:
```
python -m client.test_ping --label A
python -m client.test_ping --label B
```
Cada una debe mostrar **su propia** IP virtual en la respuesta (ej. A ve `10.8.0.2`, B ve `10.8.0.3`) y nunca la del otro. Si se cruzan, hay un bug de enrutamiento que reportar.

### Qué reportar si algo falla
- Logs completos de la terminal del servidor y del cliente.
- Si es un error de Windows/red: correr `Get-NetAdapter`, `Get-NetNat`, `Get-NetIPInterface` en PowerShell (como administrador) y compartir la salida.