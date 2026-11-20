"""Compara el SHA-256 de un archivo con el hash esperado.

    python scripts/verificar_hash.py archivo.pdf [hash_esperado]     (sin hash: solo lo imprime)
Si el equipo ya tiene su propio módulo de SHA-256, basta con que aplicacion/cripto.py:sha256_archivo() lo use."""
import sys

from _comun import RAIZ  # noqa: F401

from aplicacion import cripto

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    h = cripto.sha256_archivo(sys.argv[1])
    print(h)
    if len(sys.argv) > 2:
        ok = h == sys.argv[2].lower()
        print("COINCIDE: archivo íntegro" if ok else "NO COINCIDE: el archivo fue modificado")
        raise SystemExit(0 if ok else 1)
