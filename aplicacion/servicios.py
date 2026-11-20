"""Lógica de negocio: comprobantes firmados, lectura íntegra de productos y copias personalizadas."""
import json
import re
from decimal import Decimal, InvalidOperation

from cryptography.exceptions import InvalidTag
from flask import current_app

from . import cripto, fingerprint
from .db import ahora, get_db


class ErrorIntegridad(Exception):
    pass


# ---------------------------------------------------------------- categorías del catálogo
# nombre -> (ícono, clase de color de la interfaz)
CATEGORIAS = {
    "Libros electrónicos": ("📘", "azul"),
    "Manuales": ("🛠️", "rojo"),
    "Documentos técnicos": ("📐", "morado"),
    "Apuntes": ("📝", "amarillo"),
    "Guías": ("🧭", "verde"),
    "Material educativo": ("🎓", "naranja"),
}
FORMATOS = {"pdf": "PDF", "md": "Markdown", "txt": "Texto", "png": "Imagen PNG"}


# ---------------------------------------------------------------- pago simulado con tarjeta (NO se guarda nada de la tarjeta)
TARJETAS_PRUEBA = {                     # números de prueba que simulan una respuesta del banco
    "4000000000000002": "Tarjeta declinada por el banco emisor.",
    "4000000000009995": "Fondos insuficientes.",
    "4000000000000069": "La tarjeta está vencida según el banco emisor.",
}


def _luhn(numero: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(numero)):
        n = int(d)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def marca_tarjeta(numero: str):
    if re.match(r"^3[47]", numero):
        return "American Express", (15,), 4
    if re.match(r"^(5[1-5]|2(2[2-9][1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720))", numero):
        return "Mastercard", (16,), 3
    if numero.startswith("4"):
        return "Visa", (13, 16, 19), 3
    return None, (16,), 3


def validar_tarjeta(titular, numero, vencimiento, cvv, hoy=None):
    """Valida como lo haría una pasarela. Devuelve (aprobado: bool, motivo: str, marca: str|None).

    Los datos solo viven durante esta función: no se escriben en la BD, en la bitácora ni en archivos."""
    import datetime
    hoy = hoy or datetime.date.today()
    titular = (titular or "").strip()
    numero = re.sub(r"[\s-]", "", numero or "")
    cvv = (cvv or "").strip()
    if not re.fullmatch(r"[A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .]{3,60}", titular) or len(titular.split()) < 2:
        return False, "El nombre del titular está incompleto (nombre y apellido como aparece en la tarjeta).", None
    if not numero.isdigit():
        return False, "El número de tarjeta contiene caracteres no válidos.", None
    marca, longitudes, largo_cvv = marca_tarjeta(numero)
    if len(numero) not in longitudes:
        mayores = [n for n in longitudes if n > len(numero)]
        falta = min(mayores) - len(numero) if mayores else 0
        detalle = f"falta{'n' if falta != 1 else ''} {falta} dígito{'s' if falta != 1 else ''}" if falta else "sobran dígitos"
        return False, f"El número de tarjeta está incompleto ({detalle}).", marca
    if not _luhn(numero):
        return False, "El número de tarjeta no es válido (dígito verificador incorrecto).", marca
    m = re.fullmatch(r"\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*", vencimiento or "")
    if not m or not 1 <= int(m.group(1)) <= 12:
        return False, "La fecha de vencimiento no es válida (formato MM/AA).", marca
    mes, anio = int(m.group(1)), int(m.group(2))
    anio = anio + 2000 if anio < 100 else anio
    if (anio, mes) < (hoy.year, hoy.month):
        return False, "La tarjeta está vencida.", marca
    if anio > hoy.year + 20:
        return False, "La fecha de vencimiento no es válida.", marca
    if not re.fullmatch(r"\d{%d}" % largo_cvv, cvv):
        return False, f"El código de seguridad (CVV) debe tener {largo_cvv} dígitos.", marca
    if numero in TARJETAS_PRUEBA:
        return False, TARJETAS_PRUEBA[numero], marca
    return True, "Pago autorizado.", marca


# ---------------------------------------------------------------- utilidades
def dinero(centavos):
    return f"${centavos / 100:,.2f}"


def parsear_precio(texto):
    """'149.90' -> 14990 centavos. Devuelve None si no es un importe válido (0 a 100,000)."""
    try:
        d = Decimal(texto.strip().replace(",", ""))
    except (InvalidOperation, AttributeError):
        return None
    if d < 0 or d > 100000 or d != d.quantize(Decimal("0.01")):
        return None
    return int(d * 100)


def _aj():
    return current_app.config["AJUSTES"]


def clave_productos():
    return cripto.clave_simetrica(_aj().CLAVES_DIR, "productos.key")


def clave_fingerprint():
    return cripto.clave_simetrica(_aj().CLAVES_DIR, "fingerprint.key")


def _privada():
    ext = current_app.extensions.setdefault("tienda", {})
    if "privada" not in ext:
        ext["privada"] = cripto.cargar_privada(_aj().CLAVES_DIR)
    return ext["privada"]


def publica():
    ext = current_app.extensions.setdefault("tienda", {})
    if "publica" not in ext:
        ext["publica"] = cripto.cargar_publica(_aj().CLAVES_PUBLICAS_DIR)
    return ext["publica"]


# ---------------------------------------------------------------- comprobantes
def emitir_comprobante(order_id):
    """Genera el comprobante de una orden pagada y lo firma con la clave privada (RSA-PSS/SHA-256)."""
    db = get_db()
    o = db.execute("SELECT o.*, u.name, u.email FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
                   (order_id,)).fetchone()
    pago = db.execute("SELECT * FROM payments WHERE order_id = ? AND status = 'APROBADO' ORDER BY id DESC LIMIT 1",
                      (order_id,)).fetchone()
    items = db.execute("SELECT p.id, p.name, i.price_cents FROM order_items i JOIN products p ON p.id = i.product_id "
                       "WHERE i.order_id = ? ORDER BY p.id", (order_id,)).fetchall()
    contenido = {
        "numero_orden": o["id"],
        "usuario": {"id": o["user_id"], "nombre": o["name"], "correo": o["email"]},
        "productos": [{"id": i["id"], "nombre": i["name"], "precio_centavos": i["price_cents"]} for i in items],
        "total_centavos": o["total_cents"],
        "moneda": _aj().MONEDA,
        "fecha": pago["created_at"],
        "referencia_transaccion": pago["transaction_reference"],
    }
    texto = cripto.canonico(contenido)
    firma = cripto.firmar(texto, _privada())
    db.execute("INSERT INTO receipts(order_id, content, signature, key_id, created_at) VALUES(?,?,?,?,?)",
               (order_id, texto, firma, cripto.id_clave_publica(publica()), ahora()))
    return contenido


def comprobante_valido(fila) -> bool:
    """Verifica con la CLAVE PÚBLICA que el comprobante almacenado no fue modificado."""
    return cripto.verificar(fila["content"], fila["signature"], publica())


def comprobante_exportable(fila) -> dict:
    return {"comprobante": json.loads(fila["content"]), "firma": fila["signature"],
            "algoritmo": "RSA-PSS-SHA256", "key_id": fila["key_id"]}


ALGORITMO = "RSA-PSS-SHA256"
CAMPOS_DOCUMENTO = {"comprobante", "firma", "algoritmo", "key_id"}


class _ClaveDuplicada(ValueError):
    pass


def _sin_duplicados(pares):
    """Rechaza JSON con claves repetidas: json.loads se quedaría con la última y un campo "editado" pasaría inadvertido."""
    d = {}
    for k, v in pares:
        if k in d:
            raise _ClaveDuplicada(k)
        d[k] = v
    return d


def leer_documento(datos: bytes):
    """Decodifica el .json de un comprobante. Devuelve (doc, error)."""
    try:
        texto = datos.decode("utf-8-sig")                     # acepta el BOM que agrega el Bloc de notas
    except UnicodeDecodeError:
        return None, "El archivo no es texto UTF-8."
    try:
        doc = json.loads(texto, object_pairs_hook=_sin_duplicados)
    except _ClaveDuplicada as e:
        return None, f"El archivo tiene el campo «{e}» repetido (posible manipulación)."
    except ValueError:
        return None, "El archivo no es un JSON válido."
    if not isinstance(doc, dict):
        return None, "El archivo no tiene la estructura de un comprobante."
    return doc, None


def diferencias_con_bd(contenido: dict):
    """Compara lo firmado con los registros ACTUALES de la orden. Devuelve una lista de diferencias (vacía = coincide).

    La firma prueba que el comprobante no cambió; esta comparación detecta además si alguien alteró la BASE DE DATOS
    (orden, partidas o pago) después de emitirlo."""
    db = get_db()
    try:
        oid = int(contenido["numero_orden"])
    except (KeyError, TypeError, ValueError):
        return ["el comprobante no indica un número de orden válido"]
    o = db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if o is None:
        return [f"la orden #{oid} no existe en la plataforma"]
    dif = []
    usuario = contenido.get("usuario") or {}
    if usuario.get("id") != o["user_id"]:
        dif.append(f"comprador: firmado #{usuario.get('id')} · registrado #{o['user_id']}")
    if contenido.get("total_centavos") != o["total_cents"]:
        dif.append(f"total: firmado {contenido.get('total_centavos')} · registrado {o['total_cents']} centavos")
    if o["status"] not in ("PAGADA", "COMPLETADA"):
        dif.append(f"estado de la orden: {o['status']} (debería estar pagada)")
    items = db.execute("SELECT product_id, price_cents FROM order_items WHERE order_id = ? ORDER BY product_id", (oid,)).fetchall()
    firmados = sorted((p.get("id"), p.get("precio_centavos")) for p in contenido.get("productos") or [] if isinstance(p, dict))
    if firmados != [(i["product_id"], i["price_cents"]) for i in items]:
        dif.append("productos o precios de la orden no coinciden con lo firmado")
    pago = db.execute("SELECT * FROM payments WHERE transaction_reference = ?", (contenido.get("referencia_transaccion"),)).fetchone()
    if pago is None or pago["order_id"] != oid or pago["status"] != "APROBADO":
        dif.append("la referencia de transacción no corresponde a un pago aprobado de esta orden")
    elif pago["amount_cents"] != o["total_cents"]:
        dif.append(f"monto del pago: {pago['amount_cents']} · total de la orden {o['total_cents']} centavos")
    recibo = db.execute("SELECT content FROM receipts WHERE order_id = ?", (oid,)).fetchone()
    if recibo is None:
        dif.append("la plataforma no tiene registrado un comprobante para esta orden")
    elif recibo["content"] != cripto.canonico(contenido):
        dif.append("el comprobante guardado en la plataforma es distinto al presentado")
    return dif


def analizar_documento(doc: dict) -> dict:
    """Verificación ESTRICTA de un comprobante descargado. Devuelve {'valido', 'motivo', 'datos', 'diferencias'}.

    Es válido solo si: tiene exactamente los campos esperados, el algoritmo y la clave son los de la plataforma,
    la firma RSA-PSS verifica sobre el contenido y lo firmado coincide con los registros de la orden."""
    r = {"valido": False, "motivo": "", "datos": None, "diferencias": []}
    if not isinstance(doc, dict) or set(doc) != CAMPOS_DOCUMENTO:
        extra = sorted(set(doc) - CAMPOS_DOCUMENTO) if isinstance(doc, dict) else []
        faltan = sorted(CAMPOS_DOCUMENTO - set(doc)) if isinstance(doc, dict) else []
        r["motivo"] = "Estructura alterada" + (f": campos agregados {extra}" if extra else "") + (f": faltan {faltan}" if faltan else "") + "."
        return r
    if not isinstance(doc["comprobante"], dict) or not isinstance(doc["firma"], str):
        r["motivo"] = "Estructura alterada: 'comprobante' o 'firma' tienen un tipo incorrecto."
        return r
    r["datos"] = doc["comprobante"]
    if doc["algoritmo"] != ALGORITMO:
        r["motivo"] = f"El algoritmo declarado fue modificado ({doc['algoritmo']!r})."
        return r
    if doc["key_id"] != cripto.id_clave_publica(publica()):
        r["motivo"] = "El identificador de clave no corresponde a la clave pública de esta plataforma."
        return r
    if not cripto.verificar(cripto.canonico(doc["comprobante"]), doc["firma"], publica()):
        r["motivo"] = "La firma no corresponde al contenido: el comprobante fue modificado o no lo emitió la plataforma."
        return r
    r["diferencias"] = diferencias_con_bd(doc["comprobante"])
    if r["diferencias"]:
        r["motivo"] = "La firma es auténtica, pero los registros de la orden en la plataforma no coinciden con lo firmado."
        return r
    r["valido"] = True
    r["motivo"] = "Firma auténtica y coincide con los registros de la orden."
    return r


def verificar_documento(doc: dict) -> bool:
    """Compatibilidad: True solo si el comprobante pasa la verificación estricta."""
    return analizar_documento(doc)["valido"]


# ---------------------------------------------------------------- productos
def guardar_producto_cifrado(datos: bytes, nombre_interno: str):
    ruta = _aj().PRODUCTOS_DIR / nombre_interno
    _aj().PRODUCTOS_DIR.mkdir(parents=True, exist_ok=True)
    ruta.write_bytes(cripto.cifrar(datos, clave_productos()))
    return cripto.sha256_bytes(datos)


def leer_producto(p) -> bytes:
    """Descifra el producto y comprueba su SHA-256 contra el registrado en la BD."""
    ruta = _aj().PRODUCTOS_DIR / p["file_name"]
    if ruta.resolve().parent != _aj().PRODUCTOS_DIR.resolve():
        raise ErrorIntegridad("ruta fuera del directorio de productos")
    try:
        datos = cripto.descifrar(ruta.read_bytes(), clave_productos())
    except (InvalidTag, FileNotFoundError) as e:
        raise ErrorIntegridad(f"archivo alterado o ausente ({type(e).__name__})")
    if cripto.sha256_bytes(datos) != p["file_hash"]:
        raise ErrorIntegridad("el SHA-256 no coincide con el registrado")
    return datos


def copia_personalizada(p, user_id, order_id):
    """Devuelve (bytes de la copia con fingerprint, huella_hex)."""
    original = leer_producto(p)
    return fingerprint.incrustar(original, p["file_type"], user_id, order_id, p["id"], clave_fingerprint())


_VALIDADORES = {
    "png": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
    "pdf": lambda d: d.startswith(b"%PDF-"),
}


def contenido_coherente(tipo, datos: bytes) -> bool:
    """El contenido debe coincidir con la extensión declarada (no se confía en el nombre)."""
    if tipo in _VALIDADORES:
        return _VALIDADORES[tipo](datos)
    try:
        datos.decode("utf-8")
        return b"\x00" not in datos
    except UnicodeDecodeError:
        return False


def nombre_descarga_seguro(nombre):
    nombre = re.sub(r"[^A-Za-z0-9._\- ]", "_", nombre.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])[:100]
    return nombre or "producto"
