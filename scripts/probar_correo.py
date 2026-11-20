"""Prueba la configuración SMTP enviando un código de ejemplo.

    python scripts/probar_correo.py tu@correo.com
"""
import sys

from _comun import crear_app

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    app = crear_app()
    with app.app_context():
        from aplicacion import correo
        if not correo.smtp_configurado():
            print("No hay SMTP configurado: el mensaje irá a registros/correo_simulado.log (crea claves_privadas/correo.ini).")
        try:
            via = correo.enviar_codigo_verificacion(sys.argv[1], "Prueba", "123456", 30)
            print(f"Correo enviado ({via}). Revisa la bandeja de entrada y la carpeta de spam.")
        except Exception as e:  # noqa: BLE001
            raise SystemExit(f"No se pudo enviar: {type(e).__name__}: {e}")
