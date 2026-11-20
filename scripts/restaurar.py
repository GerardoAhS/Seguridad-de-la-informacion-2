"""Restaura un respaldo.   python scripts/restaurar.py respaldos/respaldo_XXXX.zip [--forzar]

Verifica la firma del manifiesto y el SHA-256 de cada archivo ANTES de restaurar, y al final comprueba que la BD
y todos los productos son utilizables."""
import argparse
from pathlib import Path

from _comun import RAIZ  # noqa: F401

from aplicacion import respaldo
from aplicacion.ajustes import Ajustes

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("zip")
    ap.add_argument("--forzar", action="store_true", help="sobrescribir la base de datos existente")
    a = ap.parse_args()
    try:
        r = respaldo.restaurar(Path(a.zip), Ajustes(), forzar=a.forzar)
    except respaldo.ErrorRespaldo as e:
        raise SystemExit(f"RESTAURACIÓN CANCELADA: {e}")
    print("Restauración correcta:")
    for k, v in r.items():
        print(f"  {k}: {v}")
