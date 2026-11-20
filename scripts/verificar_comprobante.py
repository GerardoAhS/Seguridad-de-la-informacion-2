"""Verificación DESDE AFUERA de un comprobante firmado (no usa la aplicación ni la base de datos).

    python scripts/verificar_comprobante.py comprobante_orden_1.json [claves_publicas/firma_comprobantes.pub.pem]

Solo necesita la clave PÚBLICA. Es lo que haría un tercero (o el cliente) para comprobar autenticidad e integridad.
Es estricta: rechaza campos agregados o repetidos, un algoritmo o key_id cambiados y, claro, cualquier cambio al contenido."""
import json
import sys
from pathlib import Path

from _comun import RAIZ

from aplicacion import cripto

CAMPOS = {"comprobante", "firma", "algoritmo", "key_id"}


def _sin_duplicados(pares):
    d = {}
    for k, v in pares:
        if k in d:
            raise ValueError(f"campo repetido: {k}")
        d[k] = v
    return d


def verificar(ruta, pub_dir):
    try:
        doc = json.loads(Path(ruta).read_bytes().decode("utf-8-sig"), object_pairs_hook=_sin_duplicados)
    except (ValueError, UnicodeDecodeError) as e:
        return False, f"archivo ilegible o alterado ({e})"
    if not isinstance(doc, dict) or set(doc) != CAMPOS:
        return False, "estructura alterada (campos agregados o faltantes)"
    pub = cripto.cargar_publica(pub_dir)
    if doc["algoritmo"] != "RSA-PSS-SHA256":
        return False, "algoritmo modificado"
    if doc["key_id"] != cripto.id_clave_publica(pub):
        return False, "key_id no corresponde a la clave pública"
    if not isinstance(doc["comprobante"], dict) or not isinstance(doc["firma"], str):
        return False, "estructura alterada"
    if not cripto.verificar(cripto.canonico(doc["comprobante"]), doc["firma"], pub):
        return False, "la firma no corresponde al contenido"
    return True, ""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    pub_dir = Path(sys.argv[2]).parent if len(sys.argv) > 2 else RAIZ / "claves_publicas"
    ok, motivo = verificar(sys.argv[1], pub_dir)
    print("FIRMA VÁLIDA: el comprobante es auténtico y no fue modificado." if ok else
          f"FIRMA INVÁLIDA: {motivo}. El comprobante fue modificado o no fue emitido por la plataforma.")
    raise SystemExit(0 if ok else 1)
