"""Servidor HTTPS de la tienda (certificado emitido por la CA local).

    python scripts/ejecutar_servidor.py [--puerto 5443] [--host 127.0.0.1]

Para producción se recomienda un servidor WSGI (gunicorn/waitress) detrás de nginx con el mismo certificado.
"""
import argparse
import ssl

from _comun import crear_app

from aplicacion.ajustes import Ajustes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--puerto", type=int, default=5443)
    a = ap.parse_args()
    aj = Ajustes()
    crt, key = aj.CERTS_DIR / "server.crt", aj.CERTS_DIR / "server.key"
    if not crt.exists():
        raise SystemExit("Faltan los certificados. Ejecuta primero: python scripts/inicializar.py")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(crt), str(key))
    app = crear_app()
    print(f"Tienda segura en https://{a.host}:{a.puerto}  (TLS >= 1.2, certificado de la CA local)")
    app.run(host=a.host, port=a.puerto, ssl_context=ctx, debug=False, threaded=True)


if __name__ == "__main__":
    main()
