# Arquitectura propuesta

```text
client/       Cliente UDP e integración de handshake y cifrado
server/       Servidor UDP e integración de sesiones
vpn_crypto/   Responsabilidad de cifrado y autenticación
protocol/     Contrato compartido de paquetes, constantes y errores
core/         Sesiones, direcciones IP virtuales y logging
firewall/     Kill Switch simulado y, más adelante, reglas Linux
api/          API REST de administración
tests/        Pruebas automatizadas
docs/         Arquitectura, pruebas y preparación de la defensa
```

La separación mantiene la criptografía independiente del transporte UDP. Esto
permite probar `vpn_crypto` con bytes en memoria y detectar errores antes de
integrarlo con sockets.

## Flujo previsto de V1

1. El cliente crea un socket UDP y contacta al servidor en el puerto 51820.
2. Cliente y servidor realizan el handshake y autentican la sesión.
3. X25519 y una función de derivación producen claves de sesión.
4. El gestor registra la sesión y asigna una IP virtual simulada.
5. Los payloads se cifran con ChaCha20-Poly1305 y viajan dentro del formato
   definido en `protocol/packets.py`.
6. El receptor valida sesión, secuencia y tag antes de aceptar el payload.
7. La API consulta estado no sensible; el Kill Switch de V1 solo se simula.

El módulo actual implementa solamente el paso 1 con un mensaje de texto y una
respuesta `ACK`. No contiene aún ninguna promesa de seguridad.
