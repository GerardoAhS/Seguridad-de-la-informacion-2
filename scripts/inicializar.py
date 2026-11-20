"""Prepara TODO el ambiente desde cero: claves, CA y certificados TLS, base de datos, usuarios y productos de prueba.

    python scripts/inicializar.py              # primera vez
    python scripts/inicializar.py --reset      # borra BD y productos y vuelve a sembrar (las claves se conservan)
    python scripts/inicializar.py --ip 192.168.1.50   # certificado válido también para esa IP (dos computadoras)
"""
import argparse
import shutil

from _comun import RAIZ, crear_app

from aplicacion import cripto, db
from aplicacion.ajustes import Ajustes


def generar_certificados(aj, ip):
    import config as cfg            # infraestructura/config.py
    import generar_pki              # infraestructura/generar_pki.py (CA local + servidor + casos negativos)
    cfg.CERTS = str(aj.CERTS_DIR)
    generar_pki.main(ip)
    shutil.copy(aj.CERTS_DIR / "ca.crt", aj.CLAVES_PUBLICAS_DIR / "ca.crt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--ip", default="127.0.0.1")
    ap.add_argument("--solo-datos", action="store_true", help="no regenerar certificados")
    a = ap.parse_args()
    aj = Ajustes()
    for d in (aj.CLAVES_DIR, aj.CLAVES_PUBLICAS_DIR, aj.CERTS_DIR, aj.PRODUCTOS_DIR, aj.RESPALDOS_DIR, aj.EVIDENCIAS_DIR, aj.REGISTROS_DIR):
        d.mkdir(parents=True, exist_ok=True)

    print("[1/5] Claves (firma RSA-3072, cifrado de productos, HMAC del fingerprint)")
    if not (aj.CLAVES_DIR / "firma_privada.pem").exists():
        cripto.generar_par_firma(aj.CLAVES_DIR, aj.CLAVES_PUBLICAS_DIR)
    cripto.clave_simetrica(aj.CLAVES_DIR, "productos.key")
    cripto.clave_simetrica(aj.CLAVES_DIR, "fingerprint.key")

    print("[2/5] CA local y certificados TLS")
    if not a.solo_datos and (a.reset or not (aj.CERTS_DIR / "server.crt").exists() or a.ip != "127.0.0.1"):
        generar_certificados(aj, a.ip)

    print("[3/5] Base de datos")
    if a.reset:
        aj.DB_PATH.unlink(missing_ok=True)
        for f in aj.PRODUCTOS_DIR.glob("*.enc"):
            f.unlink()
    db.crear_esquema(aj.DB_PATH, aj.SCHEMA)

    print("[4/5] Usuarios y productos de prueba")
    app = crear_app()
    from aplicacion import datos_demo
    with app.app_context():
        datos_demo.sembrar_usuarios()
        datos_demo.sembrar_productos()

    print("[5/5] Listo.\n")
    print("Inicia el servidor HTTPS con:   python scripts/ejecutar_servidor.py")
    print("Y abre https://localhost:5443  (el navegador debe confiar en certificados/ca.crt; ver README)")
    print("\nUsuarios de PRUEBA (correo / contraseña):")
    from aplicacion.datos_demo import USUARIOS_PRUEBA
    for correo, _n, rol, pw in USUARIOS_PRUEBA:
        print(f"  {rol:<14} {correo:<24} {pw}")


if __name__ == "__main__":
    main()
