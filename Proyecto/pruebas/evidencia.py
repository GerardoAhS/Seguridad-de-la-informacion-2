"""Recolector de evidencias: cada prueba agrega aquí lo que demostró y el ejecutor lo vuelca a evidencias/."""
REGISTRO = []      # (prueba, texto)
ARCHIVOS = {}      # nombre -> bytes (artefactos de evidencia: comprobantes, copias con huella, etc.)


def anotar(prueba, texto):
    REGISTRO.append((prueba, texto))
