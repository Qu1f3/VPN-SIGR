"""
Interfaz gráfica mínima para el cliente VPN.

Corre la conexión en un hilo de fondo (VPNClient.connect() bloquea
hasta que se llame a disconnect()), y usa root.after() para actualizar
los widgets desde ese hilo de forma segura -- Tkinter no permite tocar
widgets directamente desde un hilo que no sea el principal.
"""
from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from client.vpn_client import VPNClient, DEFAULT_TIMEOUT_SECONDS

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51820


class VPNGui:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("VPN-SIGR")
        self.root.geometry("380x300")
        self.root.resizable(False, False)

        self.client: VPNClient | None = None
        self.client_thread: threading.Thread | None = None

        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Servidor:").grid(row=0, column=0, sticky="w", pady=4)
        self.host_var = tk.StringVar(value=os.environ.get("VPN_HOST", DEFAULT_HOST))
        ttk.Entry(frame, textvariable=self.host_var).grid(row=0, column=1, pady=4, sticky="ew")

        ttk.Label(frame, text="Puerto:").grid(row=1, column=0, sticky="w", pady=4)
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(frame, textvariable=self.port_var).grid(row=1, column=1, pady=4, sticky="ew")

        ttk.Label(frame, text="Usuario:").grid(row=2, column=0, sticky="w", pady=4)
        self.username_var = tk.StringVar(value=os.environ.get("VPN_USERNAME", ""))
        ttk.Entry(frame, textvariable=self.username_var).grid(row=2, column=1, pady=4, sticky="ew")

        ttk.Label(frame, text="Contraseña:").grid(row=3, column=0, sticky="w", pady=4)
        self.password_var = tk.StringVar(value=os.environ.get("VPN_PASSWORD", ""))
        ttk.Entry(frame, textvariable=self.password_var, show="•").grid(row=3, column=1, pady=4, sticky="ew")

        frame.columnconfigure(1, weight=1)

        self.connect_button = ttk.Button(frame, text="Conectar", command=self.on_connect_click)
        self.connect_button.grid(row=4, column=0, columnspan=2, pady=(20, 4), sticky="ew")

        self.disconnect_button = ttk.Button(
            frame, text="Desconectar", command=self.on_disconnect_click, state="disabled"
        )
        self.disconnect_button.grid(row=5, column=0, columnspan=2, pady=4, sticky="ew")

        self.status_var = tk.StringVar(value="Desconectado")
        ttk.Label(
            frame, textvariable=self.status_var, wraplength=340, foreground="#555555"
        ).grid(row=6, column=0, columnspan=2, pady=(20, 0), sticky="w")

        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _set_status(self, message: str):
        # root.after() salta de vuelta al hilo principal de Tkinter --
        # necesario porque _set_status se llama desde el hilo de la VPN.
        self.root.after(0, lambda: self.status_var.set(message))

    def on_connect_click(self):
        host = self.host_var.get().strip()
        port_text = self.port_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not host or not port_text or not username or not password:
            messagebox.showerror("VPN-SIGR", "Completa todos los campos.")
            return

        try:
            port = int(port_text)
        except ValueError:
            messagebox.showerror("VPN-SIGR", "El puerto debe ser un número.")
            return

        self.client = VPNClient(
            host, port, username, password,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            on_status=self._set_status,
        )

        self.connect_button.config(state="disabled")
        self.disconnect_button.config(state="normal")

        self.client_thread = threading.Thread(target=self._run_client, daemon=True)
        self.client_thread.start()

    def _run_client(self):
        try:
            self.client.connect()
        except Exception as error:
            self._set_status(f"Error: {error}")
            self.root.after(0, lambda: messagebox.showerror("VPN-SIGR", str(error)))
        finally:
            self.root.after(0, self._on_disconnected_ui)

    def _on_disconnected_ui(self):
        self.connect_button.config(state="normal")
        self.disconnect_button.config(state="disabled")

    def on_disconnect_click(self):
        if self.client:
            self.client.disconnect()

    def on_close(self):
        if self.client and self.client.connected:
            self.client.disconnect()
            # Le da un instante al hilo de la VPN para limpiar rutas/DNS
            # antes de cerrar la ventana.
            if self.client_thread:
                self.client_thread.join(timeout=5)
        self.root.destroy()


def main():
    root = tk.Tk()
    VPNGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()