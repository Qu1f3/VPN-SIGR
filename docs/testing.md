# Pruebas

## V1, módulo 1: UDP en localhost

La prueba manual y la prueba automatizada se pueden ejecutar tanto en Windows
como en Ubuntu. Consulta los comandos en el `README.md`.

Resultado esperado del cliente:

```text
Respuesta de 127.0.0.1:51820: ACK: hola VPN
```

En dos VMs, el servidor deberá iniciarse con `--host 0.0.0.0` y el cliente usar
la IP privada de la VM servidor. Esa validación corresponde a V2; no hace falta
abrir todavía el puerto al exterior.
