"""Criptografía aplicada. Solo se usan bibliotecas estándar (hashlib, cryptography): ningún algoritmo está implementado a mano.

  - SHA-256 de archivos ............ integridad de los productos
  - AES-256-GCM .................... confidencialidad de los productos almacenados (cifrado en reposo)
  - RSA-PSS + SHA-256 .............. firma digital de comprobantes (no repudio)
  - HMAC-SHA-256 (en fingerprint.py) autenticidad de la huella incrustada
"""
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------- hash de archivos (SHA-256)
def sha256_bytes(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def sha256_archivo(ruta) -> str:
    """SHA-256 de un archivo leyéndolo por bloques (sirve para archivos grandes)."""
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloque)
    return h.hexdigest()


# ---------------------------------------------------------------- manejo de claves
def _escribir_privado(ruta: Path, contenido: bytes):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(ruta), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # permisos restringidos desde la creación
    with os.fdopen(fd, "wb") as f:
        f.write(contenido)


def clave_simetrica(claves_dir: Path, nombre: str) -> bytes:
    """Clave aleatoria de 32 bytes guardada fuera del código y del repositorio. Se crea la primera vez."""
    ruta = claves_dir / nombre
    if not ruta.exists():
        _escribir_privado(ruta, os.urandom(32))
    return ruta.read_bytes()


def generar_par_firma(claves_dir: Path, publicas_dir: Path, passphrase: bytes | None = None):
    """Crea el par RSA-3072 de firma. La privada queda en claves_privadas/ (no se publica); la pública, en claves_publicas/."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cifrado = (serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption())
    _escribir_privado(claves_dir / "firma_privada.pem",
                      priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, cifrado))
    publicas_dir.mkdir(parents=True, exist_ok=True)
    (publicas_dir / "firma_comprobantes.pub.pem").write_bytes(
        priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def cargar_privada(claves_dir: Path):
    pw = os.environ.get("FIRMA_PASSPHRASE")
    return serialization.load_pem_private_key((claves_dir / "firma_privada.pem").read_bytes(),
                                              pw.encode() if pw else None)


def cargar_publica(publicas_dir: Path):
    return serialization.load_pem_public_key((publicas_dir / "firma_comprobantes.pub.pem").read_bytes())


def id_clave_publica(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


# ---------------------------------------------------------------- cifrado en reposo (AES-256-GCM)
def cifrar(datos: bytes, clave: bytes, contexto: bytes = b"producto") -> bytes:
    nonce = os.urandom(12)                      # nonce único por archivo
    return nonce + AESGCM(clave).encrypt(nonce, datos, contexto)


def descifrar(blob: bytes, clave: bytes, contexto: bytes = b"producto") -> bytes:
    """Lanza cryptography.exceptions.InvalidTag si el archivo fue alterado o la clave no corresponde."""
    return AESGCM(clave).decrypt(blob[:12], blob[12:], contexto)


# ---------------------------------------------------------------- firma digital de comprobantes (RSA-PSS)
def canonico(obj) -> str:
    """Serialización determinista: mismo contenido => mismos bytes => misma firma verificable."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def firmar(texto: str, privada) -> str:
    return base64.b64encode(privada.sign(texto.encode("utf-8"), _PSS, hashes.SHA256())).decode()


def verificar(texto: str, firma_b64: str, publica) -> bool:
    try:
        publica.verify(base64.b64decode(firma_b64), texto.encode("utf-8"), _PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False
