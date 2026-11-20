"""Servidor de administración remota con SSH REAL (paramiko).

 - AUTENTICACIÓN: usuario + contraseña (hash scrypt, aaa.py)
 - AUTORIZACIÓN : solo roles con permiso 'ssh:login'; cada comando exige 'ssh:<comando>'
 - REGISTRO     : cada conexión, intento de login, acceso y operación queda en auditoria.log
 - El canal va CIFRADO (a diferencia de mandar la contraseña por un socket normal).

    python ssh_server.py
"""
import logging
import os
import socket
import threading

import paramiko

import aaa
import config
from auditoria import leer, registrar

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # silencia mensajes internos de paramiko

COMANDOS = ("status", "restart-service", "view-logs")


def cargar_clave_host(ruta):
    """Clave que identifica al servidor SSH (se crea la primera vez)."""
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    if os.path.exists(ruta):
        return paramiko.RSAKey.from_private_key_file(ruta)
    clave = paramiko.RSAKey.generate(2048)
    clave.write_private_key_file(ruta)
    return clave


def ejecutar_comando(usuario, rol, comando, ip):
    """Devuelve (código_de_salida, salida, error). Cada operación administrativa se autoriza y se registra."""
    comando = comando.strip()
    if comando not in COMANDOS:
        registrar("OPERACION_ADMIN", usuario, ip, comando, "RECHAZADO", "comando inexistente")
        return 127, "", f"bash: {comando}: comando no reconocido\n"
    if not aaa.autorizar(usuario, rol, f"ssh:{comando}", ip, f"ssh:{comando}"):
        registrar("OPERACION_ADMIN", usuario, ip, comando, "RECHAZADO", "sin permiso")
        return 126, "", f"Permiso denegado: el rol '{rol}' no puede ejecutar '{comando}'\n"
    if comando == "status":
        salida = "[INFO] Estado: ssh=activo tls=activo vpn=activo\n"
    elif comando == "restart-service":
        salida = "[ACCION CRITICA] Servicio de red reiniciado (simulado).\n"
    else:
        salida = "[AUDITORIA - ultimas lineas]\n" + "\n".join(leer()[-8:]) + "\n"
    registrar("OPERACION_ADMIN", usuario, ip, comando, "OK")
    return 0, salida, ""


class Interfaz(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip, self.usuario, self.rol = ip, None, None
        self.comando, self.evento = None, threading.Event()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        rol = aaa.autenticar(username, password, self.ip, "ssh")                      # ¿quién eres?
        if rol is None:
            return paramiko.AUTH_FAILED
        if not aaa.autorizar(username, rol, "ssh:login", self.ip, "ssh"):            # ¿puedes entrar por SSH?
            return paramiko.AUTH_FAILED
        self.usuario, self.rol = username, rol
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.comando = command.decode("utf-8", errors="replace")
        self.evento.set()
        return True


class ServidorSSH:
    def __init__(self, host="0.0.0.0", puerto=0, ruta_clave=None):
        self.host, self.puerto = host, puerto
        self.clave_host = cargar_clave_host(ruta_clave or config.cert("ssh_host_key"))
        self.detenido = threading.Event()

    def iniciar(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.puerto))
        self.sock.listen(5)
        self.sock.settimeout(0.3)
        self.puerto = self.sock.getsockname()[1]
        threading.Thread(target=self._aceptar, daemon=True).start()
        return self

    def detener(self):
        self.detenido.set()
        self.sock.close()

    def _aceptar(self):
        while not self.detenido.is_set():
            try:
                cliente, direccion = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._atender, args=(cliente, direccion[0]), daemon=True).start()

    def _atender(self, sock, ip):
        registrar("SSH_CONEXION", ip=ip, recurso="ssh", detalle="intento de conexion")
        transporte = paramiko.Transport(sock)
        transporte.add_server_key(self.clave_host)
        interfaz = Interfaz(ip)
        try:
            transporte.start_server(server=interfaz)
            while transporte.is_active():
                canal = transporte.accept(1)          # un canal por cada comando del cliente
                if canal is None:
                    continue
                if interfaz.usuario and interfaz.evento.wait(10):
                    interfaz.evento.clear()
                    codigo, salida, error = ejecutar_comando(interfaz.usuario, interfaz.rol, interfaz.comando, ip)
                    if salida:
                        canal.sendall(salida.encode("utf-8"))
                    if error:
                        canal.sendall_stderr(error.encode("utf-8"))
                    canal.send_exit_status(codigo)
                canal.close()
        except (paramiko.SSHException, EOFError, OSError) as e:
            registrar("SSH_ERROR_SESION", ip=ip, resultado="ERROR", detalle=repr(e)[:80])
        finally:
            if interfaz.usuario:
                registrar("SSH_DESCONEXION", interfaz.usuario, ip, "ssh")
            transporte.close()


if __name__ == "__main__":
    srv = ServidorSSH("0.0.0.0", config.PUERTO_SSH).iniciar()
    print(f"[SERVIDOR SSH] Escuchando conexiones administrativas en el puerto {srv.puerto} (Ctrl+C para salir)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.detener()
