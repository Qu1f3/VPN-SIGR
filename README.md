# VPN académica en Python

Proyecto educativo con arquitectura inspirada en WireGuard. Se construirá por
versiones y módulos; no pretende reemplazar una VPN auditada para producción.

## Estado actual

V1, módulo 1: comunicación UDP básica entre cliente y servidor, todavía sin
cifrado. El servidor escucha por defecto en `127.0.0.1:51820/UDP`, recibe un
mensaje y responde con `ACK`.

## Prueba manual en localhost

En una terminal:

```powershell
python server/server.py
```

En otra terminal:

```powershell
python client/client.py --message "hola VPN"
```

Prueba automatizada:

```powershell
python -m unittest tests.test_udp -v
```

Después de instalar `requirements.txt`, la misma prueba también funciona con:

```powershell
python -m pytest tests/test_udp.py -v
```

En Ubuntu se usan los mismos comandos con `python3`.

> Aviso: en este módulo Wireshark podrá leer el mensaje porque aún no está
> cifrado. Eso es esperado y cambiará en el módulo de cifrado del túnel.
