"""Extrae el fingerprint de una copia sospechosa e identifica usuario, orden y producto.

    python scripts/recuperar_fingerprint.py copia_sospechosa.pdf
"""
import sqlite3
import sys
from pathlib import Path

from _comun import RAIZ  # noqa: F401

from aplicacion import cripto, fingerprint
from aplicacion.ajustes import Ajustes

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    aj = Ajustes()
    ruta = Path(sys.argv[1])
    a = fingerprint.analizar(ruta.read_bytes(), cripto.clave_simetrica(aj.CLAVES_DIR, "fingerprint.key"))
    datos = a["huella"]
    if not datos:
        if a["cargas_invalidas"]:
            raise SystemExit("Hay una marca con el formato de la plataforma pero su HMAC no es válido "
                             "(alterada, o emitida con otra fingerprint.key).")
        raise SystemExit("No se encontró una huella auténtica (copia original, huella eliminada, o archivo ajeno a la plataforma).")
    con = sqlite3.connect(str(aj.DB_PATH))
    u = con.execute("SELECT email, name FROM users WHERE id = ?", (datos["user_id"],)).fetchone()
    p = con.execute("SELECT name FROM products WHERE id = ?", (datos["product_id"],)).fetchone()
    print("HUELLA RECUPERADA")
    print(f"  Usuario : #{datos['user_id']} {u[1] + ' <' + u[0] + '>' if u else '(no existe)'}")
    print(f"  Orden   : #{datos['order_id']}")
    print(f"  Producto: #{datos['product_id']} {p[0] if p else ''}")
