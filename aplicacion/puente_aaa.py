"""INTEGRACIÓN: el módulo AAA/SSH de infraestructura/ autentica contra la MISMA tabla users de la tienda.

Así existe una sola fuente de identidades: el ADMINISTRADOR y el OPERADOR de la tienda son también los usuarios
que pueden entrar por SSH (con los permisos de infraestructura/aaa.py: ADMINISTRADOR todo; OPERADOR solo status y
view-logs; CLIENTE se autentica pero NO tiene permiso de SSH). Las contraseñas siguen siendo hash (Argon2id/scrypt).
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "infraestructura"))

from . import seguridad  # noqa: E402


def instalar(ajustes):
    import aaa

    def proveedor(usuario, password):
        con = sqlite3.connect(str(ajustes.DB_PATH))
        con.row_factory = sqlite3.Row
        try:
            fila = con.execute("SELECT password_hash, role, status FROM users WHERE email = ?",
                               (usuario.strip().lower(),)).fetchone()
        finally:
            con.close()
        if fila is None:
            seguridad.verificar_falso(password)
            return None
        ok = seguridad.verificar_password(password, fila["password_hash"]) and fila["status"] == "ACTIVO"
        return fila["role"] if ok else None

    aaa.PROVEEDOR_EXTERNO = proveedor
    return aaa
