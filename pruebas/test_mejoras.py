"""Pruebas de la versión 2: pago con tarjeta sin almacenar datos, verificación estricta de comprobantes,
rastreo de copias en casos reales y catálogo con categorías."""
import io
import json
import os
import re

from . import entorno as E
from .evidencia import anotar
from aplicacion import cripto, fingerprint


def _subir(nav, url, nombre, contenido):
    return nav.c.post(url, data={"csrf_token": nav.token(), "archivo": (io.BytesIO(contenido), nombre)},
                      base_url=E.B, content_type="multipart/form-data")


def _orden_pendiente(nav, productos=(2,)):
    for pid in productos:
        nav.post(f"/carrito/agregar/{pid}")
    r = nav.post("/ordenes")
    return int(r.headers["Location"].split("?")[0].rsplit("/", 1)[1])


# ---------------------------------------------------------------- pago con tarjeta
def test_pago_con_tarjeta_valida_y_rechaza_datos_incompletos():
    ana = E.Navegador.como(E.ANA)
    oid = _orden_pendiente(ana)
    casos = {
        "falta un dígito": (dict(E.TARJETA_OK, numero="4242 4242 4242 424"), "falta 1 dígito"),
        "dígito verificador": (dict(E.TARJETA_OK, numero="4242 4242 4242 4241"), "no es válido"),
        "vencida": (dict(E.TARJETA_OK, vencimiento="01/20"), "vencida"),
        "CVV corto": (dict(E.TARJETA_OK, cvv="12"), "CVV"),
        "sin apellido": (dict(E.TARJETA_OK, titular="Ana"), "titular"),
        "banco declina": (E.TARJETA_DECLINADA, "declinada"),
    }
    vistos = {}
    for nombre, (datos, esperado) in casos.items():
        r = ana.post(f"/ordenes/{oid}/pagar", datos)
        assert r.status_code == 302 and "pago=rechazado" in r.headers["Location"], nombre
        pagina = ana.get(r.headers["Location"]).text
        assert "No se pudo completar el pago" in pagina and esperado in pagina, (nombre, esperado)
        vistos[nombre] = E.consulta("SELECT detail FROM payments WHERE order_id = ? ORDER BY id DESC LIMIT 1", (oid,))[0][0]
    assert E.consulta("SELECT status FROM orders WHERE id = ?", (oid,))[0][0] == "PENDIENTE"
    assert not E.consulta("SELECT 1 FROM receipts WHERE order_id = ?", (oid,))
    r = ana.post(f"/ordenes/{oid}/pagar", E.TARJETA_OK)
    assert "pago=aprobado" in r.headers["Location"] and "¡Pago completado!" in ana.get(r.headers["Location"]).text
    assert E.consulta("SELECT status FROM orders WHERE id = ?", (oid,))[0][0] == "PAGADA"
    # ningún dato de tarjeta queda guardado: ni en la BD, ni en la bitácora, ni en archivos de registro
    import sqlite3
    volcado = "\n".join(sqlite3.connect(str(E.AJ.DB_PATH)).iterdump())
    registros = "".join(p.read_text(encoding="utf-8", errors="ignore") for p in E.AJ.REGISTROS_DIR.glob("*.log"))
    for dato in ("4242424242424242", "4242 4242 4242 4242", "4242 4242 4242 424", "4000000000000002", "Ana Cliente Prueba"):
        assert dato not in volcado and dato not in registros, dato
    anotar("Pago con tarjeta (simulado)", "Rechazos con motivo visible: " + "; ".join(f"{k} -> «{v}»" for k, v in vistos.items()) +
           ". Con 4242 4242 4242 4242 el pago se aprueba. Ni el número, ni el titular, ni el CVV aparecen en la BD ni en los registros.")


def test_cliente_no_puede_forzar_el_resultado_del_pago():
    ana = E.Navegador.como(E.ANA)
    oid = _orden_pendiente(ana)
    r = ana.post(f"/ordenes/{oid}/pagar", {"resultado": "aprobar"})          # el formulario viejo ya no sirve
    assert "pago=rechazado" in r.headers["Location"]
    assert E.consulta("SELECT status FROM orders WHERE id = ?", (oid,))[0][0] == "PENDIENTE"
    anotar("Pago: sin atajos", "Enviar resultado=aprobar sin datos de tarjeta deja la orden PENDIENTE (pago rechazado).")


# ---------------------------------------------------------------- verificación estricta de comprobantes
def test_verificacion_estricta_detecta_cualquier_cambio():
    ana = E.Navegador.como(E.ANA)
    oid = E.comprar(ana, (1, 2))
    crudo = ana.get(f"/comprobantes/{oid}/descargar").data
    doc = json.loads(crudo)

    def verificar(cuerpo):
        r = _subir(ana, "/verificar", "c.json", cuerpo if isinstance(cuerpo, bytes) else json.dumps(cuerpo, ensure_ascii=False, indent=2).encode())
        return "Firma válida" in r.text

    def cambio(f):
        d = json.loads(crudo)
        f(d)
        return d

    assert verificar(crudo)
    assert verificar(json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode())          # solo formato: sigue válido
    assert verificar(b"\xef\xbb\xbf" + crudo)                                                     # BOM del Bloc de notas: válido
    invalidos = {
        "total": cambio(lambda d: d["comprobante"].__setitem__("total_centavos", 1)),
        "nombre": cambio(lambda d: d["comprobante"]["usuario"].__setitem__("nombre", "Otra Persona")),
        "precio de un producto": cambio(lambda d: d["comprobante"]["productos"][0].__setitem__("precio_centavos", 100)),
        "campo agregado": cambio(lambda d: d.__setitem__("descuento", "100%")),
        "campo agregado dentro": cambio(lambda d: d["comprobante"].__setitem__("nota", "pagado")),
        "key_id": cambio(lambda d: d.__setitem__("key_id", "0000000000000000")),
        "algoritmo": cambio(lambda d: d.__setitem__("algoritmo", "NINGUNO")),
        "firma": cambio(lambda d: d.__setitem__("firma", d["firma"][:-4] + "AAA=")),
    }
    for nombre, d in invalidos.items():
        assert not verificar(d), nombre
    # clave duplicada: json.loads se quedaría con la última y el "cambio" pasaría inadvertido
    texto = crudo.decode()
    duplicado = texto.replace('"total_centavos":', '"total_centavos": 1, "total_centavos":', 1)
    assert not verificar(duplicado.encode())
    # alteración de la BASE DE DATOS después de emitir el comprobante
    E.ejecutar("UPDATE orders SET total_cents = 1 WHERE id = ?", (oid,))
    assert not verificar(crudo)
    pagina = ana.get(f"/comprobantes/{oid}").text
    assert "LA ORDEN FUE ALTERADA" in pagina and "total" in pagina
    E.ejecutar("UPDATE orders SET total_cents = (SELECT SUM(price_cents) FROM order_items WHERE order_id = ?) WHERE id = ?", (oid, oid))
    assert verificar(crudo)
    anotar("Verificación estricta de comprobantes", "Válido: original, re-formateado y con BOM. Inválido: " + ", ".join(invalidos) +
           ", clave duplicada y orden alterada en la BD después de emitir el comprobante.")


# ---------------------------------------------------------------- rastreo de copias en casos reales
def test_rastreo_de_copias_en_casos_reales():
    ana = E.Navegador.como(E.ANA)
    uid = E.consulta("SELECT id FROM users WHERE email = ?", (E.ANA[0],))[0][0]
    oid = E.comprar(ana, (1, 3, 4))
    md, pdf, png = (ana.get(f"/descargas/{oid}/{p}").data for p in (1, 3, 4))
    comp = ana.get(f"/comprobantes/{oid}/descargar").data
    adm = E.Navegador.como(E.ADMIN)

    def rastrear(nombre, datos):
        return _subir(adm, "/admin/fingerprint", nombre, datos).text

    casos = {
        "PDF renombrado a .txt": rastrear("documento.txt", pdf),
        "PNG sin extensión": rastrear("imagen", png),
        "Markdown con fin de línea Windows": rastrear("guia.md", md.replace(b"\n", b"\r\n")),
        "Markdown guardado en UTF-16": rastrear("guia.md", md.decode("utf-8").encode("utf-16")),
        "Comprobante .json": rastrear("comprobante.json", comp),
    }
    for nombre, html in casos.items():
        assert "Copia identificada" in html and E.ANA[0] in html and f"#{oid}" in html, nombre
    # archivo ORIGINAL (sin huella) y huella emitida con OTRA clave: mensajes que explican la causa
    original = (E.AJ.PRODUCTOS_DIR / E.consulta("SELECT file_name FROM products WHERE id = 2")[0][0]).read_bytes()
    from aplicacion import cripto as C
    clave = C.clave_simetrica(E.AJ.CLAVES_DIR, "productos.key")
    texto_original = C.descifrar(original, clave)
    assert "ORIGINAL" in rastrear("apuntes.txt", texto_original)
    ajena, _ = fingerprint.incrustar(texto_original, "txt", uid, oid, 2, os.urandom(32))
    assert "HMAC no es válido" in rastrear("apuntes.txt", ajena)
    assert "No se encontró una huella" in rastrear("x.txt", b"un texto cualquiera")
    anotar("Rastreo de copias (casos reales)", "Identificado: " + ", ".join(casos) +
           ". El original sin huella, una huella de otra clave y un archivo ajeno se reportan con su causa.")


# ---------------------------------------------------------------- catálogo
def test_catalogo_con_categorias_y_busqueda():
    n = E.Navegador()
    total = E.consulta("SELECT COUNT(*) FROM products WHERE status = 'ACTIVO'")[0][0]
    cats = {r[0] for r in E.consulta("SELECT DISTINCT category FROM products")}
    assert total >= 18 and {"Libros electrónicos", "Manuales", "Documentos técnicos", "Apuntes", "Guías", "Material educativo"} <= cats
    pagina = n.get("/?cat=Manuales").text
    assert "Manual de Git" in pagina and "Apuntes de cálculo" not in pagina
    assert "Apuntes de bases de datos" in n.get("/?q=SQL").text
    assert n.get("/?q=%25%27%22<script>").status_code == 200 and "<script>" not in n.get("/?q=<script>").text.split("<main>")[1]
    # cada producto del catálogo nuevo se descifra, pasa su SHA-256 y recibe huella
    ana = E.Navegador.como(E.ANA)
    nuevos = [r[0] for r in E.consulta("SELECT id FROM products WHERE id BETWEEN 5 AND 18")]
    oid = E.comprar(ana, nuevos)
    clave = cripto.clave_simetrica(E.AJ.CLAVES_DIR, "fingerprint.key")
    for pid in nuevos:
        r = ana.get(f"/descargas/{oid}/{pid}")
        assert r.status_code == 200 and fingerprint.analizar(r.data, clave)["huella"]["product_id"] == pid, pid
    anotar("Catálogo ampliado", f"{total} productos en 6 categorías; filtro por categoría y búsqueda funcionan (y escapan la entrada); "
           f"los {len(nuevos)} productos nuevos se descargan con huella recuperable.")
