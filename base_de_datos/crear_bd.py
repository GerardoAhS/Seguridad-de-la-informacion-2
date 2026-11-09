"""Crea la base de datos y carga los datos de prueba.

Uso:  python base_de_datos/crear_bd.py
Si la base ya existe, se borra y se vuelve a crear.
"""
import hashlib
import os
import sqlite3

from argon2 import PasswordHasher

CARPETA = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(CARPETA)
RUTA_BD = os.path.join(CARPETA, "tienda.db")
CARPETA_PRODUCTOS = os.path.join(RAIZ, "productos")

ph = PasswordHasher()

# Usuarios de prueba (uno por rol). Solo para desarrollo.
USUARIOS = [
    ("cliente@tienda.com",  "Cliente123!",  "Cliente de Prueba",  "CLIENTE"),
    ("operador@tienda.com", "Operador123!", "Operador de Prueba", "OPERADOR"),
    ("admin@tienda.com",    "Admin123!",    "Administrador",      "ADMINISTRADOR"),
]

PRODUCTOS = [
    ("Guía rápida de redes", "Apuntes introductorios de redes y modelo OSI.", 49.0, "guia_redes.txt"),
    ("Manual básico de Linux", "Comandos esenciales, permisos y usuarios.", 79.0, "manual_linux.txt"),
    ("Apuntes de criptografía", "Cifrado, hashes y firma digital.", 99.0, "apuntes_criptografia.txt"),
    ("Introducción a Python", "Fundamentos del lenguaje con ejercicios.", 59.0, "intro_python.txt"),
]


def sha256_archivo(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            h.update(bloque)
    return h.hexdigest()


def main():
    if os.path.exists(RUTA_BD):
        os.remove(RUTA_BD)

    con = sqlite3.connect(RUTA_BD)
    with open(os.path.join(CARPETA, "esquema.sql"), encoding="utf-8") as f:
        con.executescript(f.read())

    for email, clave, nombre, rol in USUARIOS:
        con.execute(
            "INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)",
            (email, ph.hash(clave), nombre, rol),
        )

    for nombre, desc, precio, archivo in PRODUCTOS:
        hash_archivo = sha256_archivo(os.path.join(CARPETA_PRODUCTOS, archivo))
        con.execute(
            "INSERT INTO products (name, description, price, file_name, file_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (nombre, desc, precio, archivo, hash_archivo),
        )

    con.commit()
    con.close()
    print(f"Base de datos creada en {RUTA_BD}")
    print(f"  {len(USUARIOS)} usuarios y {len(PRODUCTOS)} productos de prueba")


if __name__ == "__main__":
    main()
