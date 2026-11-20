"""Utilidades compartidas por los scripts: ruta del proyecto y creación de la app."""
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "infraestructura"))


def crear_app():
    from aplicacion import create_app
    return create_app()
