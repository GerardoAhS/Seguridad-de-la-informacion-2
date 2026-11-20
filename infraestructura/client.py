"""Cliente de la aplicación. En modo TLS valida el certificado del servidor ANTES de enviar nada.

    python client.py plano
    python client.py tls
    python client.py tls --host 192.168.1.50 --usuario carlos_rrhh --password rrhh2026 --accion nomina
    python client.py tls --sin-ca        (no confía en nuestra CA -> debe rechazar)
    python client.py tls --inseguro      (NO valida el certificado: demuestra el riesgo)
"""
import argparse
import getpass
import socket
import ssl

import config
from auditoria import registrar


def consultar(host, puerto, usuario, password, accion, modo="tls", ca=None, inseguro=False, nombre=None):
    """Devuelve (codigo, mensaje, info). Lanza ssl.SSLCertVerificationError si el certificado no es confiable."""
    crudo = socket.create_connection((host, puerto), timeout=10)
    sock, info = crudo, {"modo": modo}
    try:
        if modo == "tls":
            # 1. El contexto confía SOLO en la CA indicada (cafile) y verifica fechas, cadena y nombre
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if inseguro:                     # NUNCA en producción: desactiva la validación
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                # 2. Handshake: aquí se valida el certificado del servidor
                sock = ctx.wrap_socket(crudo, server_hostname=nombre or host)
            except ssl.SSLCertVerificationError as e:
                registrar("CERTIFICADO_RECHAZADO", ip=host, recurso="app-tls", resultado="RECHAZADO",
                          detalle=e.verify_message)
                raise
            cert = sock.getpeercert() or {}
            info.update(version=sock.version(), cifrado=sock.cipher()[0],
                        sujeto=dict(x[0] for x in cert.get("subject", ())).get("commonName"),
                        emisor=dict(x[0] for x in cert.get("issuer", ())).get("commonName"),
                        caduca=cert.get("notAfter"))
        sock.sendall(f"{usuario}|{password}|{accion}\n".encode("utf-8"))
        codigo, mensaje = sock.recv(4096).decode("utf-8").split("|", 1)
        return int(codigo), mensaje, info
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modo", choices=["plano", "tls"])
    ap.add_argument("--host", default=config.ip_servidor())
    ap.add_argument("--puerto", type=int)
    ap.add_argument("--ca", default=config.cert("ca.crt"), help="certificado de la CA de la organización")
    ap.add_argument("--sin-ca", action="store_true", help="usar solo las CA del sistema (no incluye la nuestra)")
    ap.add_argument("--nombre", help="nombre esperado en el certificado (por defecto = --host)")
    ap.add_argument("--inseguro", action="store_true")
    ap.add_argument("--usuario")
    ap.add_argument("--password")
    ap.add_argument("--accion", choices=["publico", "nomina"])
    a = ap.parse_args()

    usuario = a.usuario or input("Usuario [carlos_rrhh]: ").strip() or "carlos_rrhh"
    password = a.password or getpass.getpass("Contraseña: ")
    accion = a.accion or input("Acción (publico / nomina) [publico]: ").strip() or "publico"
    puerto = a.puerto or (config.PUERTO_TLS if a.modo == "tls" else config.PUERTO_PLANO)

    print(f"\n[CLIENTE] Conectando a {a.host}:{puerto} en modo {a.modo.upper()}...")
    try:
        codigo, mensaje, info = consultar(a.host, puerto, usuario, password, accion, a.modo,
                                          None if a.sin_ca else a.ca, a.inseguro, a.nombre)
    except ssl.SSLCertVerificationError as e:
        print(f"[CLIENTE] [X] CERTIFICADO RECHAZADO: {e.verify_message}")
        print("[CLIENTE]     Conexion abortada: no se envio ninguna credencial.")
        raise SystemExit(2)
    except (ConnectionError, OSError) as e:
        raise SystemExit(f"[CLIENTE] No se pudo conectar: {e}")
    if a.modo == "tls":
        print(f"[CLIENTE] [OK] Certificado verificado. {info['version']} / {info['cifrado']}")
        print(f"          Servidor: {info['sujeto']} | emitido por: {info['emisor']} | caduca: {info['caduca']}")
    else:
        print("[CLIENTE] [!] Canal SIN CIFRAR: cualquiera en la red puede leer tu contraseña.")
    print(f"[CLIENTE] Respuesta: {codigo} - {mensaje}")


if __name__ == "__main__":
    main()
