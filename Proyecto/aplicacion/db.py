"""Acceso a la base de datos. TODAS las consultas usan parámetros (?), nunca texto concatenado (anti inyección SQL)."""
import datetime
import sqlite3

from flask import current_app, g


def ahora():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def en_minutos(minutos):
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutos)
    return t.strftime("%Y-%m-%d %H:%M:%S")


def conectar(ruta):
    con = sqlite3.connect(str(ruta), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def get_db():
    if "db" not in g:
        g.db = conectar(current_app.config["AJUSTES"].DB_PATH)
    return g.db


def cerrar_db(_exc=None):
    con = g.pop("db", None)
    if con is not None:
        con.close()


# Columnas agregadas después de la primera versión: se añaden solas a una base de datos existente (no se pierde nada).
_MIGRACIONES = [
    ("users", "email_verified", "INTEGER NOT NULL DEFAULT 0", "UPDATE users SET email_verified = 1"),   # cuentas previas ya operaban
    ("products", "category", "TEXT NOT NULL DEFAULT 'Material educativo'", None),
    ("products", "highlights", "TEXT NOT NULL DEFAULT ''", None),
    ("payments", "detail", "TEXT NOT NULL DEFAULT ''", None),
    ("password_resets", "code_hash", "TEXT NOT NULL DEFAULT ''", None),
    ("password_resets", "attempts", "INTEGER NOT NULL DEFAULT 0", None),
]


def migrar(con):
    for tabla, columna, tipo, despues in _MIGRACIONES:
        cols = {c[1] for c in con.execute(f"PRAGMA table_info({tabla})")}
        if cols and columna not in cols:
            con.execute(f"ALTER TABLE {tabla} ADD COLUMN {columna} {tipo}")
            if despues:
                con.execute(despues)
    con.commit()


def crear_esquema(ruta_db, ruta_schema):
    ruta_db.parent.mkdir(parents=True, exist_ok=True)
    con = conectar(ruta_db)
    existentes = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if existentes:
        migrar(con)                         # primero se actualizan las tablas viejas; luego se crean las que falten
    with open(ruta_schema, encoding="utf-8") as f:
        con.executescript(f.read())
    con.commit()
    con.close()


def get_setting(clave, defecto):
    fila = get_db().execute("SELECT value FROM settings WHERE key = ?", (clave,)).fetchone()
    return type(defecto)(fila["value"]) if fila else defecto


def set_setting(clave, valor):
    get_db().execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     (clave, str(valor)))
