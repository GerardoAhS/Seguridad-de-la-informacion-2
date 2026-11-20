"""Respaldo y restauración de la información crítica (disponibilidad).

El respaldo es un .zip con:
    base_de_datos/tienda.db   instantánea CONSISTENTE (API de respaldo de SQLite, segura aunque la app esté en uso)
    productos/*.enc           productos digitales (ya cifrados con AES-256-GCM)
    manifest.json             SHA-256 de cada archivo
    manifest.sig              firma RSA-PSS del manifiesto (detecta respaldos alterados)
NO incluye claves privadas: se respaldan aparte y fuera de línea (sin ellas los productos cifrados no se pueden abrir).
"""
import datetime
import hashlib
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from . import cripto
from .ajustes import Ajustes


class ErrorRespaldo(Exception):
    pass


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def crear_respaldo(aj: Ajustes) -> Path:
    aj.RESPALDOS_DIR.mkdir(parents=True, exist_ok=True)
    sello = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    destino = aj.RESPALDOS_DIR / f"respaldo_{sello}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / "tienda.db"
        origen = sqlite3.connect(str(aj.DB_PATH))
        copia = sqlite3.connect(str(snap))
        origen.backup(copia)                                  # instantánea consistente
        copia.close()
        origen.close()
        archivos = {"base_de_datos/tienda.db": snap.read_bytes()}
        for f in sorted(aj.PRODUCTOS_DIR.glob("*.enc")):
            archivos[f"productos/{f.name}"] = f.read_bytes()
        manifiesto = {"creado": datetime.datetime.now(datetime.timezone.utc).isoformat(), "version": 1,
                      "archivos": {k: _sha(v) for k, v in archivos.items()}}
        texto = cripto.canonico(manifiesto)
        with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as z:
            for k, v in archivos.items():
                z.writestr(k, v)
            z.writestr("manifest.json", texto)
            if (aj.CLAVES_DIR / "firma_privada.pem").exists():
                z.writestr("manifest.sig", cripto.firmar(texto, cripto.cargar_privada(aj.CLAVES_DIR)))
    return destino


def verificar_respaldo(ruta: Path, aj: Ajustes) -> dict:
    """Comprueba firma del manifiesto y SHA-256 de cada archivo. Lanza ErrorRespaldo si algo no coincide."""
    with zipfile.ZipFile(ruta) as z:
        nombres = set(z.namelist())
        if "manifest.json" not in nombres:
            raise ErrorRespaldo("el respaldo no tiene manifiesto")
        texto = z.read("manifest.json").decode("utf-8")
        if "manifest.sig" in nombres:
            if not cripto.verificar(texto, z.read("manifest.sig").decode(), cripto.cargar_publica(aj.CLAVES_PUBLICAS_DIR)):
                raise ErrorRespaldo("la firma del manifiesto NO es válida (respaldo alterado)")
        manifiesto = json.loads(texto)
        for nombre, esperado in manifiesto["archivos"].items():
            if nombre not in nombres:
                raise ErrorRespaldo(f"falta {nombre}")
            if _sha(z.read(nombre)) != esperado:
                raise ErrorRespaldo(f"el hash de {nombre} no coincide (archivo alterado)")
    return manifiesto


def restaurar(ruta: Path, aj: Ajustes, forzar=False) -> dict:
    manifiesto = verificar_respaldo(ruta, aj)                 # primero se valida, después se toca el sistema
    if aj.DB_PATH.exists() and not forzar:
        raise ErrorRespaldo("ya existe una base de datos; usa --forzar para sobrescribirla")
    aj.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    aj.PRODUCTOS_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ruta) as z:
        tmp = aj.DB_PATH.with_suffix(".restaurando")
        tmp.write_bytes(z.read("base_de_datos/tienda.db"))
        tmp.replace(aj.DB_PATH)
        for nombre in manifiesto["archivos"]:
            if nombre.startswith("productos/"):
                (aj.PRODUCTOS_DIR / Path(nombre).name).write_bytes(z.read(nombre))
    return resumen(aj)


def resumen(aj: Ajustes) -> dict:
    """Comprueba que lo restaurado es utilizable: integridad de la BD y cada producto descifra con el hash esperado."""
    con = sqlite3.connect(str(aj.DB_PATH))
    con.row_factory = sqlite3.Row
    r = {"integridad_bd": con.execute("PRAGMA integrity_check").fetchone()[0]}
    for tabla in ("users", "products", "orders", "payments", "receipts", "downloads", "security_events"):
        r[tabla] = con.execute(f"SELECT COUNT(*) FROM {tabla}").fetchone()[0]       # nombres fijos, no vienen del usuario
    clave = cripto.clave_simetrica(aj.CLAVES_DIR, "productos.key")
    buenos = 0
    for p in con.execute("SELECT file_name, file_hash FROM products"):
        try:
            if _sha(cripto.descifrar((aj.PRODUCTOS_DIR / p["file_name"]).read_bytes(), clave)) == p["file_hash"]:
                buenos += 1
        except Exception:
            pass
    r["productos_verificados"] = buenos
    con.close()
    return r
