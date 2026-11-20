"""Servidor de la aplicación: modo PLANO (sin protección) o TLS (certificado firmado por nuestra CA).

    python server.py plano
    python server.py tls
    python server.py tls --cert certs/expired.crt --key certs/expired.key    (probar un certificado malo)
"""
import argparse
import socket
import ssl
import threading

import aaa
import config
from auditoria import registrar

# acción -> (permiso necesario, contenido)
ACCIONES = {
    "publico": ("app:publico", "Boletin publico de la organizacion."),
    "nomina": ("app:nomina", "CONFIDENCIAL: nomina del trimestre."),
}


class Servidor:
    def __init__(self, modo="tls", host="0.0.0.0", puerto=0, cert=None, key=None):
        self.modo, self.host, self.puerto = modo, host, puerto
        self.ctx = None
        if modo == "tls":
            # 1. Contexto TLS del servidor: aquí se carga SU certificado y su clave privada
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ctx.load_cert_chain(cert or config.cert("server.crt"), key or config.cert("server.key"))
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
            threading.Thread(target=self._atender, args=(cliente, direccion), daemon=True).start()

    def _atender(self, sock, direccion):
        ip, conn = direccion[0], sock
        try:
            sock.settimeout(10)
            if self.ctx:
                try:
                    # 2. Handshake TLS: si el cliente rechaza nuestro certificado, falla aquí
                    conn = self.ctx.wrap_socket(sock, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    registrar("TLS_HANDSHAKE_FALLIDO", ip=ip, recurso="app-tls", resultado="RECHAZADO",
                              detalle=str(e)[:80])
                    return
                detalle = f"{conn.version()} / {conn.cipher()[0]}"
            else:
                detalle = "SIN CIFRADO"
            registrar("CONEXION", ip=ip, recurso=f"app-{self.modo}", detalle=detalle)

            datos = conn.recv(4096).decode("utf-8")
            try:
                usuario, password, accion = datos.strip().split("|")
            except ValueError:
                conn.sendall(b"400|Formato invalido")
                return
            rol = aaa.autenticar(usuario, password, ip, f"app-{self.modo}")          # AUTENTICACIÓN
            if rol is None:
                resp = "401|Credenciales invalidas"
            elif accion not in ACCIONES:
                resp = "404|Accion inexistente"
            else:
                permiso, texto = ACCIONES[accion]
                if aaa.autorizar(usuario, rol, permiso, ip, f"app:{accion}"):         # AUTORIZACIÓN
                    resp = f"200|{texto}"
                else:
                    resp = "403|Autenticado, pero SIN autorizacion para esta accion"
            conn.sendall(resp.encode("utf-8"))
        except Exception as e:  # un cliente defectuoso no debe tumbar el servidor
            registrar("ERROR_CONEXION", ip=ip, resultado="ERROR", detalle=repr(e)[:80])
        finally:
            conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modo", choices=["plano", "tls"])
    ap.add_argument("--puerto", type=int)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    a = ap.parse_args()
    puerto = a.puerto or (config.PUERTO_TLS if a.modo == "tls" else config.PUERTO_PLANO)
    srv = Servidor(a.modo, "0.0.0.0", puerto, a.cert, a.key).iniciar()
    print(f"[SERVIDOR {a.modo.upper()}] Escuchando en el puerto {srv.puerto} (Ctrl+C para salir)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.detener()


if __name__ == "__main__":
    main()
