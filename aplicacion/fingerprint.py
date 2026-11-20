"""Fingerprinting: incrusta en el CONTENIDO de cada copia un identificador de (usuario, orden, producto).

Carga útil (20 bytes = 160 bits):
    versión(1) | user_id(4) | order_id(4) | product_id(4) | HMAC-SHA256 truncado a 7 bytes
El HMAC usa una clave secreta del servidor: nadie puede fabricar una huella válida para incriminar a otro usuario
ni modificar una huella existente sin que se detecte.

Técnicas (se elige según el tipo de archivo):
  .txt / .md  Esteganografía lingüística en Unicode: bits como caracteres de ancho cero (U+200B=0, U+200C=1,
              delimitados por U+200D) al final de varias líneas.
  .png        LSB: el bit menos significativo de cada canal RGB, con la trama repetida por toda la imagen y
              recuperada por voto mayoritario.
  .pdf        Texto invisible (modo de render 3) "FPR:<hex>" superpuesto en cada página.

Imperceptibilidad / robustez / capacidad:
  texto  invisible al leer; sobrevive a copiar-pegar de fragmentos y a renombrar; se pierde si alguien normaliza el
         texto (elimina caracteres de ancho cero) o lo reescribe a mano. Capacidad: ilimitada (se repite).
  png    cambia ±1 en cada canal (PSNR > 50 dB, invisible); sobrevive a renombrar y a re-guardar como PNG; se
         pierde con JPEG, reescalado o capturas de pantalla. Capacidad: ancho*alto*3 bits (miles de copias).
  pdf    invisible; sobrevive a renombrar y a copiar texto; se pierde al imprimir-a-imagen/OCR.
Ninguna técnica es indestructible: por eso es disuasión + trazabilidad, no DRM.
"""
import hashlib
import hmac
import io
import re
import struct

VERSION = 1
LONG_CARGA = 20
LONG_TAG = 7


class TipoNoSoportado(Exception):
    pass


# ---------------------------------------------------------------- carga útil
def crear_carga(user_id: int, order_id: int, product_id: int, clave: bytes) -> bytes:
    cuerpo = struct.pack(">BIII", VERSION, user_id, order_id, product_id)
    tag = hmac.new(clave, cuerpo, hashlib.sha256).digest()[:LONG_TAG]
    return cuerpo + tag


def validar_carga(carga: bytes, clave: bytes):
    """Devuelve {'user_id','order_id','product_id'} si la huella es auténtica; None en otro caso."""
    if len(carga) != LONG_CARGA:
        return None
    cuerpo, tag = carga[:-LONG_TAG], carga[-LONG_TAG:]
    if not hmac.compare_digest(hmac.new(clave, cuerpo, hashlib.sha256).digest()[:LONG_TAG], tag):
        return None
    ver, u, o, p = struct.unpack(">BIII", cuerpo)
    return {"user_id": u, "order_id": o, "product_id": p} if ver == VERSION else None


def _bits(datos: bytes):
    return [(b >> (7 - i)) & 1 for b in datos for i in range(8)]


def _bytes(bits):
    return bytes(sum(bit << (7 - i) for i, bit in enumerate(bits[k:k + 8])) for k in range(0, len(bits) - 7, 8))


# ---------------------------------------------------------------- texto (.txt / .md)
ZW0, ZW1, DELIM = "\u200b", "\u200c", "\u200d"
_PATRON_TEXTO = re.compile(DELIM + "([" + ZW0 + ZW1 + "]{" + str(LONG_CARGA * 8) + "})" + DELIM)


def _marca_texto(carga):
    return DELIM + "".join(ZW1 if b else ZW0 for b in _bits(carga)) + DELIM


def _incrustar_texto(datos, carga):
    texto = datos.decode("utf-8")
    marca = _marca_texto(carga)
    lineas = texto.split("\n")
    candidatas = [i for i, l in enumerate(lineas) if l.strip()]
    if not candidatas:
        return (texto + marca).encode("utf-8")
    paso = max(1, len(candidatas) // 12)                 # ~12 copias repartidas por el documento
    elegidas = candidatas[::paso] or candidatas[:1]
    for i in elegidas:
        l = lineas[i]
        cr = "\r" if l.endswith("\r") else ""
        lineas[i] = l[:len(l) - len(cr)] + marca + cr
    return "\n".join(lineas).encode("utf-8")


def _decodificar_texto(datos):
    """UTF-8 (con o sin BOM) o UTF-16 (Bloc de notas de Windows al "Guardar como Unicode")."""
    if datos.startswith((b"\xff\xfe", b"\xfe\xff")):
        codecs = ("utf-16",)
    else:
        codecs = ("utf-8-sig", "utf-16")
    for c in codecs:
        try:
            return datos.decode(c)
        except UnicodeDecodeError:
            continue
    return None


def _cargas_texto(datos):
    texto = _decodificar_texto(datos)
    if texto is None:
        return []
    return [_bytes([1 if c == ZW1 else 0 for c in m.group(1)]) for m in _PATRON_TEXTO.finditer(texto)]


def _extraer_texto(datos, clave):
    for carga in _cargas_texto(datos):
        r = validar_carga(carga, clave)
        if r:
            return r
    return None


# ---------------------------------------------------------------- PNG (LSB)
_MAGIA = 0xA5C3
_TRAMA = 16 + LONG_CARGA * 8


def _incrustar_png(datos, carga):
    from PIL import Image
    img = Image.open(io.BytesIO(datos))
    img.load()
    img = img.convert("RGB")
    raw = bytearray(img.tobytes())
    trama = [(_MAGIA >> (15 - i)) & 1 for i in range(16)] + _bits(carga)
    if len(raw) < _TRAMA * 3:
        raise ValueError("La imagen es demasiado pequeña para incrustar la huella")
    util = (len(raw) // _TRAMA) * _TRAMA                    # tramas completas; el resto no se toca
    for i in range(util):
        raw[i] = (raw[i] & 0xFE) | trama[i % _TRAMA]
    salida = Image.frombytes("RGB", img.size, bytes(raw))
    buf = io.BytesIO()
    salida.save(buf, format="PNG")
    return buf.getvalue()


def _cargas_png(datos):
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(datos))
        img.load()
    except Exception:
        return []
    raw = img.convert("RGB").tobytes()
    n = len(raw) // _TRAMA
    if n == 0:
        return []
    bits = [b & 1 for b in raw[:n * _TRAMA]]
    voto = [1 if 2 * sum(bits[k::_TRAMA]) > n else 0 for k in range(_TRAMA)]   # voto mayoritario por posición
    if sum(b << (15 - i) for i, b in enumerate(voto[:16])) != _MAGIA:
        return []
    return [_bytes(voto[16:])]


def _extraer_png(datos, clave):
    for carga in _cargas_png(datos):
        r = validar_carga(carga, clave)
        if r:
            return r
    return None


def psnr(original: bytes, modificada: bytes) -> float:
    """Relación señal-ruido en dB (>40 dB = diferencia imperceptible). Evidencia de imperceptibilidad."""
    import math
    from PIL import Image
    a = Image.open(io.BytesIO(original)).convert("RGB").tobytes()
    b = Image.open(io.BytesIO(modificada)).convert("RGB").tobytes()
    mse = sum((x - y) ** 2 for x, y in zip(a, b)) / len(a)
    return float("inf") if mse == 0 else 10 * math.log10(255 ** 2 / mse)


# ---------------------------------------------------------------- PDF (texto invisible)
_PATRON_PDF = re.compile(r"FPR:([0-9a-f]{%d})" % (LONG_CARGA * 2))


def _incrustar_pdf(datos, carga):
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    lector = PdfReader(io.BytesIO(datos))
    escritor = PdfWriter()
    for pagina in lector.pages:
        ancho, alto = float(pagina.mediabox.width), float(pagina.mediabox.height)
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=(ancho, alto))
        t = c.beginText(20, 20)
        t.setTextRenderMode(3)                                  # 3 = invisible
        t.setFont("Helvetica", 4)
        t.textLine("FPR:" + carga.hex())
        c.drawText(t)
        c.save()
        buf.seek(0)
        pagina.merge_page(PdfReader(buf).pages[0])
        escritor.add_page(pagina)
    # Copia redundante en los metadatos del documento (invisible; sobrevive si se pierde la capa de texto)
    meta = {k: v for k, v in (lector.metadata or {}).items() if isinstance(k, str)}
    meta["/FPR"] = carga.hex()
    escritor.add_metadata(meta)
    salida = io.BytesIO()
    escritor.write(salida)
    return salida.getvalue()


def _cargas_pdf(datos):
    """Busca la huella en: metadatos, texto de cada página (sin espacios intercalados) y flujos de contenido en bruto."""
    from pypdf import PdfReader
    vistas = []
    try:
        lector = PdfReader(io.BytesIO(datos))
        meta = lector.metadata or {}
        vistas.append(str(meta.get("/FPR", "")))
        for pagina in lector.pages:
            try:
                texto = pagina.extract_text() or ""
            except Exception:
                texto = ""
            vistas.append(re.sub(r"\s+", "", texto))
            try:
                vistas.append(pagina.get_contents().get_data().decode("latin-1") if pagina.get_contents() else "")
            except Exception:
                pass
    except Exception:
        pass
    vistas.append(datos.decode("latin-1"))                  # último recurso: bytes sin comprimir
    cargas = []
    for v in vistas:
        for m in _PATRON_PDF.finditer(v):
            c = bytes.fromhex(m.group(1))
            if c not in cargas:
                cargas.append(c)
    return cargas


def _extraer_pdf(datos, clave):
    for carga in _cargas_pdf(datos):
        r = validar_carga(carga, clave)
        if r:
            return r
    return None


# ---------------------------------------------------------------- interfaz pública
_INCRUSTAR = {"txt": _incrustar_texto, "md": _incrustar_texto, "png": _incrustar_png, "pdf": _incrustar_pdf}
_EXTRAER = {"txt": _extraer_texto, "md": _extraer_texto, "png": _extraer_png, "pdf": _extraer_pdf}


def tipo_de(nombre: str) -> str:
    ext = nombre.rsplit(".", 1)[-1].lower() if "." in nombre else ""
    if ext not in _INCRUSTAR:
        raise TipoNoSoportado(ext)
    return ext


def incrustar(datos: bytes, tipo: str, user_id: int, order_id: int, product_id: int, clave: bytes) -> tuple[bytes, str]:
    """Devuelve (copia_personalizada, huella_hex)."""
    carga = crear_carga(user_id, order_id, product_id, clave)
    return _INCRUSTAR[tipo](datos, carga), carga.hex()


def extraer(datos: bytes, tipo: str, clave: bytes):
    """Devuelve {'user_id','order_id','product_id'} o None si no hay huella auténtica."""
    return _EXTRAER[tipo](datos, clave)


_CARGAS = {"txt": _cargas_texto, "md": _cargas_texto, "png": _cargas_png, "pdf": _cargas_pdf}


def tipo_por_contenido(datos: bytes):
    """El tipo real del archivo según sus bytes (no se confía en la extensión: el navegador o el usuario pudo renombrarlo)."""
    if datos.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if datos[:1024].lstrip().startswith(b"%PDF-") or b"%PDF-" in datos[:1024]:
        return "pdf"
    if datos.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" not in datos[:4096]:
        return "txt"
    return None


def analizar(datos: bytes, clave: bytes):
    """Diagnóstico completo de una copia sospechosa.

    Devuelve {'tipo', 'huella' (dict o None), 'cargas_halladas' (int), 'cargas_invalidas' (int)}.
    'cargas_invalidas' > 0 significa que SÍ hay una marca con el formato de la plataforma pero su HMAC no coincide:
    fue alterada o se emitió con otra clave (p. ej. se regeneró claves_privadas/fingerprint.key).
    """
    tipo = tipo_por_contenido(datos)
    orden = [tipo] + [t for t in ("pdf", "png", "txt") if t != tipo] if tipo else ["pdf", "png", "txt"]
    halladas, invalidas = 0, 0
    for t in orden:
        for carga in _CARGAS[t](datos):
            halladas += 1
            r = validar_carga(carga, clave)
            if r:
                return {"tipo": t, "huella": r, "cargas_halladas": halladas, "cargas_invalidas": invalidas}
            invalidas += 1
    return {"tipo": tipo, "huella": None, "cargas_halladas": halladas, "cargas_invalidas": invalidas}
