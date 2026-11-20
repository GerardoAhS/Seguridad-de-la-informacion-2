"""Configuración común: rutas, puertos y la IP del servidor."""
import os

CARPETA = os.path.dirname(os.path.abspath(__file__))
CERTS = os.environ.get("CERTS_DIR", os.path.join(CARPETA, "certs"))   # el proyecto integrado lo apunta a certificados/
LOG_FILE = os.environ.get("AUDIT_LOG", os.path.join(CARPETA, "auditoria.log"))

PUERTO_PLANO = 8080   # aplicación SIN protección
PUERTO_TLS = 8443     # aplicación con TLS
PUERTO_SSH = 2222     # administración remota SSH


def cert(nombre):
    """Ruta de un archivo dentro de certs/ (lo crea generar_pki.py)."""
    return os.path.join(CERTS, nombre)


def ip_servidor():
    """IP del servidor que usan los clientes. Se cambia con el menú (opción 8) o con la variable SERVER_IP."""
    return os.environ.get("SERVER_IP", "127.0.0.1")
