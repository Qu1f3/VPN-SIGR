from datetime import datetime


class KillSwitch:
    """
    Simulación de un Kill Switch para la VPN.

    En esta primera versión no modifica reglas del sistema
    operativo. Solamente administra el estado interno del
    firewall.

    En una versión futura este módulo podrá controlar
    iptables (Linux) o Windows Firewall.
    """

    def __init__(self):
        self._enabled = False
        self._blocking = False
        self._last_change = None

    def enable(self):
        """
        Activa el Kill Switch.
        """

        self._enabled = True
        self._last_change = datetime.now()

    def disable(self):
        """
        Desactiva el Kill Switch.
        """

        self._enabled = False
        self._blocking = False
        self._last_change = datetime.now()

    def block_traffic(self):
        """
        Simula el bloqueo del tráfico de red.
        """

        if self._enabled:
            self._blocking = True
            self._last_change = datetime.now()

    def allow_traffic(self):
        """
        Permite nuevamente el tráfico.
        """

        self._blocking = False
        self._last_change = datetime.now()

    def is_enabled(self):
        """
        Indica si el Kill Switch está habilitado.
        """

        return self._enabled

    def is_blocking(self):
        """
        Indica si actualmente está bloqueando tráfico.
        """

        return self._blocking

    def status(self):
        """
        Devuelve el estado completo del Kill Switch.
        """

        return {
            "enabled": self._enabled,
            "blocking": self._blocking,
            "last_change": self._last_change
        }



# Instancia global del Kill Switch utilizada por todo el proyecto.
kill_switch = KillSwitch()
