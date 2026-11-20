"""Configuración central. Todo se puede redefinir con variables de entorno (las pruebas usan un directorio temporal)."""
import os
from pathlib import Path

RAIZ_DEFECTO = Path(__file__).resolve().parent.parent


class Ajustes:
    def __init__(self):
        raiz = Path(os.environ.get("PROYECTO_RAIZ", RAIZ_DEFECTO))
        self.RAIZ = raiz
        self.DB_PATH = Path(os.environ.get("DB_PATH", raiz / "base_de_datos" / "tienda.db"))
        self.SCHEMA = RAIZ_DEFECTO / "base_de_datos" / "schema.sql"
        self.PRODUCTOS_DIR = Path(os.environ.get("PRODUCTOS_DIR", raiz / "productos"))
        self.CLAVES_DIR = Path(os.environ.get("CLAVES_DIR", raiz / "claves_privadas"))        # NO se publica
        self.CLAVES_PUBLICAS_DIR = Path(os.environ.get("CLAVES_PUBLICAS_DIR", raiz / "claves_publicas"))
        self.CERTS_DIR = Path(os.environ.get("CERTS_DIR", raiz / "certificados"))
        self.RESPALDOS_DIR = Path(os.environ.get("RESPALDOS_DIR", raiz / "respaldos"))
        self.EVIDENCIAS_DIR = Path(os.environ.get("EVIDENCIAS_DIR", raiz / "evidencias"))
        self.REGISTROS_DIR = Path(os.environ.get("REGISTROS_DIR", raiz / "registros"))
        # Políticas (valores por defecto; el ADMINISTRADOR puede cambiar dos desde la tabla settings)
        self.SESION_MINUTOS = 30           # inactividad máxima
        self.SESION_MAX_HORAS = 8          # duración absoluta
        self.MAX_INTENTOS = 5              # intentos fallidos por cuenta
        self.VENTANA_BLOQUEO_MIN = 15
        self.RESET_MINUTOS = 15            # vigencia del token de recuperación
        self.VERIFICACION_MINUTOS = 30     # vigencia del código de confirmación de correo
        self.MAX_INTENTOS_CODIGO = 5       # intentos con un código antes de invalidarlo
        self.REENVIO_SEGUNDOS = 60         # espera mínima para pedir otro código
        self.MAX_SUBIDA_BYTES = 20 * 1024 * 1024
        # Solo para demostraciones: muestra el enlace de recuperación en pantalla (en producción se enviaría por correo)
        self.DEMO_MOSTRAR_ENLACE = os.environ.get("DEMO_MOSTRAR_ENLACE", "0") == "1"
        self.COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"
        self.MONEDA = "MXN (simulado)"
