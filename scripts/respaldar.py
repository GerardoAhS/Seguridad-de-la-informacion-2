"""Crea un respaldo (BD + productos cifrados) en respaldos/.   python scripts/respaldar.py"""
from _comun import RAIZ  # noqa: F401

from aplicacion import respaldo
from aplicacion.ajustes import Ajustes

if __name__ == "__main__":
    ruta = respaldo.crear_respaldo(Ajustes())
    print("Respaldo creado:", ruta)
    print("Recuerda: las claves de claves_privadas/ se respaldan aparte (fuera de línea).")
