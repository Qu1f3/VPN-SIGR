import ctypes
import threading

from tunneling.wintun import wintun, WINTUN_MIN_RING_CAPACITY
from tunneling import network
from tunneling import sync

# Códigos de error de Windows que NO son fallos reales, sino condiciones normales
ERROR_NO_MORE_ITEMS = 259    # No hay paquetes pendientes por leer ahora mismo
ERROR_BUFFER_OVERFLOW = 111  # El ring buffer de salida está lleno


class Adapter:

    def __init__(self):
        self.handle = None
        self.session = None
        self.name = None
        self.ip_address = None
        self.prefix_length = None
        self.pool_prefix = None
        self.nat_name = None
        self._full_tunnel_enabled = False
        self._dns_configured = False
        self._vpn_server_ip = None

        # Protege el USO real de self.session (las llamadas que tocan
        # las estructuras internas de Wintun: recibir/liberar/asignar/
        # enviar paquete) contra que close() libere la sesión al mismo
        # tiempo desde otro hilo. read_packet()/write_packet() corren
        # en hilos distintos (TunnelClient.start() y receive_loop()
        # respectivamente), y disconnect() puede llegar de un tercer
        # hilo en cualquier momento -- sin este lock, un hilo puede
        # terminar llamando a Wintun con una sesión que otro hilo ya
        # liberó (use-after-free), lo que provoca access violations.
        #
        # OJO: este lock NO envuelve la espera de wait_for_packet() --
        # esa espera debe seguir siendo interrumpible por
        # WintunEndSession (así está pensado el driver), si la
        # metiéramos dentro del lock, close() se quedaría esperando a
        # que termine una espera que nunca se puede interrumpir por
        # estar bloqueada por el propio lock que close() necesita.
        self._session_lock = threading.Lock()

    def create(self, name="VPN-SIGR", tunnel_type="VPN"):
        self.handle = wintun.WintunCreateAdapter(
            name,
            tunnel_type,
            None,
        )

        if not self.handle:
            error = ctypes.WinError(ctypes.get_last_error())
            raise RuntimeError(f"No pudo crearse el adaptador: {error}")

        self.name = name
        return self.handle

    def set_ip(self, ip_address: str, prefix_length: int = 32):
        """
        Asigna una IP a la interfaz. Por defecto usa /32 (una sola IP,
        sin subred) A PROPÓSITO: si usas un prefijo más ancho (ej. /24),
        Windows trata a cualquier otra IP de esa subred (ej. un cliente
        VPN en 10.8.0.5) como "vecino en la misma red local" y exige
        resolverla por ARP antes de poder entregarle tráfico. Wintun no
        tiene un peer real que responda ese ARP, así que cualquier
        paquete que le llegue de vuelta destinado a otra IP del pool se
        pierde en silencio — el driver nunca llega a recibirlo.

        Con /32 evitas ese problema. Usa add_pool_route() para decirle
        a Windows, por separado, qué rango de IPs adicionales (el resto
        de tus clientes VPN) debe entregarle a esta interfaz.

        Debe llamarse después de create(). Requiere permisos de
        administrador — si falla con "acceso denegado", corre el
        script como admin.
        """
        if not self.name:
            raise RuntimeError("Primero debes llamar a create().")

        network.set_adapter_ip(self.name, ip_address, prefix_length)
        self.ip_address = ip_address
        self.prefix_length = prefix_length

    def add_pool_route(self, pool_prefix: str):
        """
        Agrega una ruta explícita para el rango completo de IPs
        virtuales de tus clientes VPN (ej. "10.8.0.0/24") a través de
        este adaptador. Necesario porque set_ip() usa /32 por defecto —
        sin esto Windows no entrega por aquí el tráfico destinado a
        otras IPs del pool.
        """
        if not self.name:
            raise RuntimeError("Primero debes llamar a create().")

        network.add_route(pool_prefix, self.name)
        self.pool_prefix = pool_prefix

    def enable_internet_sharing(
        self,
        wan_interface_name: str = None,
        nat_name: str = "VPN-NAT",
        internal_prefix: str = None,
    ):
        """
        Activa reenvío de paquetes + NAT para que los clientes conectados
        a la VPN puedan navegar por internet usando la IP pública de
        este servidor. Debe llamarse después de set_ip().

        'internal_prefix' es el rango de IPs virtuales de tus clientes
        (ej. "10.8.0.0/24"). Si no lo pasas, usa el que hayas configurado
        con add_pool_route().

        'wan_interface_name' es el nombre de la interfaz por la que el
        SERVIDOR sale a internet (no el TUN). Si no la pasas, se detecta
        automáticamente buscando la interfaz con la ruta por defecto
        (0.0.0.0/0) — recomendado, especialmente en un servidor donde
        no controlas cómo se llama la interfaz de antemano.

        Nota si esto corre en un servidor rentado (VPS/cloud, ej. AWS,
        Azure, GCP): además de esto, casi siempre hay que habilitar
        "IP forwarding" / desactivar "source/destination check" desde
        el panel del proveedor. Sin eso, la capa de red virtual del
        proveedor descarta el tráfico NAT-eado aunque Windows esté bien
        configurado, porque no coincide con la IP asignada a la VM.
        """
        if not self.name or not self.ip_address:
            raise RuntimeError("Primero debes llamar a create() y set_ip().")

        internal_prefix = internal_prefix or self.pool_prefix
        if not internal_prefix:
            raise RuntimeError(
                "No se especificó el rango de IPs virtuales de los "
                "clientes. Pasa 'internal_prefix' o llama primero a "
                "add_pool_route()."
            )

        if wan_interface_name is None:
            wan_interface_name = network.get_default_interface_name()

        network.enable_forwarding_on_interface(self.name)
        network.enable_forwarding_on_interface(wan_interface_name)

        network.create_nat(nat_name, internal_prefix)

        self.nat_name = nat_name

    def enable_full_tunnel(self, server_ip: str, dns_servers: list = None):
        """
        Redirige TODO el tráfico del sistema por este túnel (cliente).
        'server_ip' es la IP real del servidor VPN al que este cliente
        está conectado -- necesaria para excluirla del túnel y evitar
        un loop de enrutamiento (el tráfico cifrado hacia el servidor
        debe seguir saliendo por la ruta original, no por el túnel que
        depende de ese mismo tráfico).

        'dns_servers' es opcional -- una lista de IPs (ej.
        ["1.1.1.1", "1.0.0.1"]). Sin esto, las consultas DNS pueden
        seguir filtrándose por fuera del túnel aunque el resto del
        tráfico ya vaya cifrado.
        """
        if not self.name:
            raise RuntimeError("Primero debes llamar a create().")

        gateway_ip, original_interface = network.get_default_gateway()

        network.pin_route_to_gateway(server_ip, gateway_ip, original_interface)
        network.enable_full_tunnel(self.name)

        self._vpn_server_ip = server_ip
        self._full_tunnel_enabled = True

        if dns_servers:
            network.set_dns(self.name, dns_servers)
            self._dns_configured = True

    def disable_full_tunnel(self):
        """
        Restaura el enrutamiento normal. Se llama automáticamente desde
        close() -- no deberías necesitar llamarlo a mano salvo que
        quieras desactivar el túnel completo sin cerrar el adaptador.
        """
        if self._full_tunnel_enabled and self.name:
            network.disable_full_tunnel(self.name)
            self._full_tunnel_enabled = False

        if self._dns_configured and self.name:
            network.reset_dns(self.name)
            self._dns_configured = False

        if self._vpn_server_ip:
            network.remove_route(self._vpn_server_ip)
            self._vpn_server_ip = None

    def start_session(self, capacity=WINTUN_MIN_RING_CAPACITY):
        """
        Debe llamarse después de create(). 'capacity' es el tamaño del
        ring buffer en bytes; tiene que ser potencia de 2 entre
        WINTUN_MIN_RING_CAPACITY y WINTUN_MAX_RING_CAPACITY.
        """
        if not self.handle:
            raise RuntimeError("Primero debes llamar a create().")

        self.session = wintun.WintunStartSession(self.handle, capacity)

        if not self.session:
            error = ctypes.WinError(ctypes.get_last_error())
            raise RuntimeError(f"No pudo iniciarse la sesión: {error}")

        return self.session

    def get_read_wait_event(self):
        """
        Devuelve el handle de evento de Windows que se activa cuando hay
        un paquete disponible para leer. Úsalo con WaitForSingleObject
        (vía ctypes o pywin32) en vez de hacer polling en un bucle
        apretado — así tu hilo no consume CPU innecesariamente.
        """
        if not self.session:
            raise RuntimeError("Primero debes llamar a start_session().")
        return wintun.WintunGetReadWaitEvent(self.session)

    def wait_for_packet(self, timeout_ms=sync.INFINITE) -> bool:
        """
        Bloquea eficientemente (CPU ~0%) hasta que haya al menos un
        paquete disponible, o hasta que pase timeout_ms.
        Devuelve True si hay datos, False si fue timeout.
        """
        event_handle = self.get_read_wait_event()
        return sync.wait(event_handle, timeout_ms)

    def read_loop(self, timeout_ms=sync.INFINITE):
        """
        Generador que entrega paquetes a medida que llegan, sin hacer
        polling. Espera al evento de lectura y luego drena TODOS los
        paquetes disponibles antes de volver a esperar, porque Wintun
        puede acumular varios paquetes entre una señal del evento y la
        siguiente.

        Si pasas un timeout_ms finito, cuando no llega nada a tiempo el
        generador entrega 'None' (en vez de bloquear para siempre) para
        que el consumidor pueda decidir qué hacer — por ejemplo, revisar
        su propio deadline total y salir del for con 'break'.
        Con timeout_ms=sync.INFINITE (default) nunca se entrega None.
        """
        while True:
            if self.session is None:
                # close() ya corrió (disconnect() desde otro hilo) --
                # no hay nada más que esperar, termina el generador
                # con calma en vez de tronar en get_read_wait_event().
                return

            got_signal = self.wait_for_packet(timeout_ms)

            if not got_signal:
                yield None
                continue

            while True:
                packet = self.read_packet()
                if packet is None:
                    break
                yield packet

    def read_packet(self):
        """
        Lee un paquete saliente generado por el sistema operativo (el que
        luego cifrarás y enviarás por tu socket hacia el peer VPN).

        Devuelve bytes, o None si no hay paquetes disponibles en este
        momento (no es un error).
        """
        with self._session_lock:
            session = self.session
            if session is None:
                # La sesión ya se cerró (disconnect() en curso en otro
                # hilo) -- no hay nada que leer, no es un error.
                return None

            size = ctypes.c_uint32()
            packet_ptr = wintun.WintunReceivePacket(session, ctypes.byref(size))

            if not packet_ptr:
                err = ctypes.get_last_error()
                if err == ERROR_NO_MORE_ITEMS:
                    return None
                raise RuntimeError(f"Error leyendo paquete: {ctypes.WinError(err)}")

            data = ctypes.string_at(packet_ptr, size.value)
            wintun.WintunReleaseReceivePacket(session, packet_ptr)
            return data

    def write_packet(self, data: bytes) -> bool:
        """
        Inyecta un paquete (ya descifrado, que llegó desde el peer VPN)
        de vuelta hacia el sistema operativo, como si viniera de la red.

        Devuelve False si el ring buffer está lleno (reintentar después),
        True si se envió correctamente.
        """
        with self._session_lock:
            session = self.session
            if session is None:
                # La sesión ya se cerró (disconnect() en curso en otro
                # hilo) -- no hay a dónde escribir. Antes esto seguía
                # de largo y le pasaba None a WintunAllocateSendPacket,
                # lo que terminaba en un access violation dentro de la
                # DLL (use-after-free de la sesión).
                return False

            size = len(data)
            packet_ptr = wintun.WintunAllocateSendPacket(session, size)

            if not packet_ptr:
                err = ctypes.get_last_error()
                if err == ERROR_BUFFER_OVERFLOW:
                    return False
                raise RuntimeError(f"Error asignando paquete de salida: {ctypes.WinError(err)}")

            ctypes.memmove(packet_ptr, data, size)
            wintun.WintunSendPacket(session, packet_ptr)
            return True

    def close(self):
        self.disable_full_tunnel()

        if self.nat_name:
            network.remove_nat(self.nat_name)
            self.nat_name = None
        with self._session_lock:
            if self.session:
                wintun.WintunEndSession(self.session)
                self.session = None
        if self.handle:
            wintun.WintunCloseAdapter(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()