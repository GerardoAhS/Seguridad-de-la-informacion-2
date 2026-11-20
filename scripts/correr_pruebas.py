"""Ejecuta TODAS las pruebas (las 13 obligatorias + extras de seguridad) y genera las evidencias en evidencias/.

    python scripts/correr_pruebas.py

No necesita pytest (aunque las funciones son compatibles con él: `python -m pytest pruebas`).
Usa un ambiente temporal aislado: no modifica tu base de datos ni tus claves reales."""
import datetime
import importlib
import platform
import sys
import time
import traceback

from _comun import RAIZ

from pruebas import entorno as E
from pruebas import evidencia

MODULOS = ["pruebas.test_obligatorias", "pruebas.test_extra", "pruebas.test_mejoras"]

OBLIGATORIAS = [  # (prefijo, prueba, resultado esperado) tal como aparece en la sección 19 del documento
    ("01", "Contraseña incorrecta", "Acceso rechazado."),
    ("02", "CLIENTE intenta una función administrativa", "Acceso rechazado."),
    ("03", "OPERADOR intenta cambiar roles", "Acceso rechazado."),
    ("04", "ADMINISTRADOR autorizado", "Operación permitida."),
    ("05", "Certificado TLS correcto", "Conexión aceptada."),
    ("06", "Certificado no confiable", "Conexión rechazada."),
    ("07", "Comprobante original", "Firma digital válida."),
    ("08", "Comprobante modificado", "Firma digital inválida."),
    ("09", "Producto descargado", "Fingerprint recuperable."),
    ("10", "CLIENTE intenta descargar producto no comprado", "Acceso rechazado."),
    ("11", "Archivo original", "Hash esperado."),
    ("12", "Archivo modificado", "Hash diferente."),
    ("13", "Restauración de respaldo", "Información crítica recuperada."),
]


def main():
    E.app()                                          # prepara el ambiente aislado (claves, CA, BD, datos)
    resultados = []
    for nombre_mod in MODULOS:
        mod = importlib.import_module(nombre_mod)
        for nombre, fn in list(vars(mod).items()):
            if nombre.startswith("test_") and callable(fn):
                t0 = time.time()
                try:
                    fn()
                    resultados.append((nombre_mod, nombre, True, "", time.time() - t0))
                    print(f"  PASS  {nombre}")
                except Exception as e:               # noqa: BLE001 - se reporta cualquier fallo
                    resultados.append((nombre_mod, nombre, False, "".join(traceback.format_exception_only(type(e), e)).strip(), time.time() - t0))
                    print(f"  FAIL  {nombre}\n{traceback.format_exc()}")

    ev = E.AJ.EVIDENCIAS_DIR
    (ev / "artefactos").mkdir(parents=True, exist_ok=True)
    notas = {n[:2]: t for n, t in evidencia.REGISTRO if n[:2].isdigit()}
    estado = {nombre: ok for _m, nombre, ok, _msg, _t in resultados}
    total, bien = len(resultados), sum(1 for r in resultados if r[2])

    L = ["# Evidencias de pruebas", "",
         f"- Fecha: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
         f"- Python {platform.python_version()} · {platform.system()}",
         f"- Resultado global: **{bien}/{total} pruebas aprobadas**", "",
         "## Pruebas mínimas obligatorias (sección 19)", "",
         "| # | Prueba | Resultado esperado | Estado |", "|---|---|---|---|"]
    for pref, prueba, esperado in OBLIGATORIAS:
        fn = next((n for n in estado if n.startswith(f"test_{pref}_")), None)
        L.append(f"| {pref} | {prueba} | {esperado} | {'✅ APROBADA' if estado.get(fn) else '❌ FALLÓ'} |")
    L += ["", "### Detalle de lo observado", ""]
    for pref, prueba, _e in OBLIGATORIAS:
        if pref in notas:
            L += [f"**{pref} · {prueba}**", "", "```", notas[pref], "```", ""]
    L += ["## Pruebas adicionales de seguridad", "", "| Prueba | Estado |", "|---|---|"]
    for m, nombre, ok, msg, _t in resultados:
        if m.endswith("test_extra"):
            L.append(f"| {nombre[5:].replace('_', ' ')} | {'✅' if ok else '❌ ' + msg[:120]} |")
    extras = [(n, t) for n, t in evidencia.REGISTRO if not n[:2].isdigit()]
    if extras:
        L += ["", "### Detalle de las pruebas adicionales", ""]
        for n, t in extras:
            L += [f"**{n}**", "", "```", t, "```", ""]
    fallos = [r for r in resultados if not r[2]]
    if fallos:
        L += ["", "## FALLOS", ""] + [f"- `{r[1]}`: {r[3]}" for r in fallos]
    (ev / "resultados_pruebas.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    for nombre, datos in evidencia.ARCHIVOS.items():
        (ev / "artefactos" / nombre).write_bytes(datos)
    filas = E.consulta("SELECT id, created_at, user_email, event, result, origin, detail FROM security_events ORDER BY id")
    with open(ev / "artefactos" / "eventos_seguridad_muestra.tsv", "w", encoding="utf-8") as f:
        f.write("id\tfecha_utc\tusuario\tevento\tresultado\torigen\tdetalle\n")
        for r in filas:
            f.write("\t".join(str(x) for x in tuple(r)) + "\n")
    log = E.AJ.REGISTROS_DIR / "auditoria.log"
    if log.exists():
        (ev / "artefactos" / "auditoria_muestra.log").write_text("".join(log.read_text(encoding="utf-8").splitlines(True)[:80]), encoding="utf-8")

    print(f"\n{bien}/{total} pruebas aprobadas. Evidencias en: {ev}")
    sys.exit(0 if bien == total else 1)


if __name__ == "__main__":
    main()
