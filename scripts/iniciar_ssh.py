"""Servidor SSH de administración (paramiko) autenticando contra los usuarios de la tienda.

    pip install paramiko
    python scripts/iniciar_ssh.py            # escucha en el puerto 2222
    python infraestructura/ssh_client.py     # (otra terminal) usuario: admin@tienda.test

Usuarios: ADMINISTRADOR = todos los comandos; OPERADOR = status y view-logs; CLIENTE = sin acceso SSH."""
import os
import threading

from _comun import RAIZ

from aplicacion import puente_aaa
from aplicacion.ajustes import Ajustes

if __name__ == "__main__":
    aj = Ajustes()
    os.environ.setdefault("CERTS_DIR", str(aj.CERTS_DIR))
    os.environ.setdefault("AUDIT_LOG", str(aj.REGISTROS_DIR / "auditoria.log"))
    puente_aaa.instalar(aj)
    import config
    import ssh_server
    srv = ssh_server.ServidorSSH("0.0.0.0", config.PUERTO_SSH).iniciar()
    print(f"[SSH] Administración remota en el puerto {srv.puerto}. Usuarios = tabla users de la tienda. Ctrl+C para salir")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.detener()
