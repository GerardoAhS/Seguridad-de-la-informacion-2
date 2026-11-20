"""Datos de prueba: usuarios de ejemplo y productos digitales generados en memoria (sin datos personales reales)."""
import io
import secrets

from . import fingerprint, seguridad, servicios
from .db import ahora, get_db

USUARIOS_PRUEBA = [  # (correo, nombre, rol, contraseña de prueba)
    ("admin@tienda.test", "Ada Administradora", "ADMINISTRADOR", "Admin-Prueba-2026"),
    ("operador@tienda.test", "Oscar Operador", "OPERADOR", "Operador-Prueba-2026"),
    ("ana@tienda.test", "Ana Cliente", "CLIENTE", "Cliente-Prueba-2026"),
    ("luis@tienda.test", "Luis Cliente", "CLIENTE", "Cliente-Prueba-2026"),
]


def sembrar_usuarios():
    con = get_db()
    for correo, nombre, rol, pw in USUARIOS_PRUEBA:
        if not con.execute("SELECT 1 FROM users WHERE email = ?", (correo,)).fetchone():
            con.execute("INSERT INTO users(email, password_hash, name, role, status, created_at, email_verified) "
                        "VALUES(?,?,?,?, 'ACTIVO', ?, 1)", (correo, seguridad.hash_password(pw), nombre, rol, ahora()))
    con.commit()


def _libro_md():
    return """# Guía práctica de criptografía aplicada

## 1. Los cinco servicios de seguridad
Confidencialidad, integridad, disponibilidad, autenticación y no repudio.
Cada mecanismo criptográfico contribuye a uno o más de estos servicios.

## 2. Funciones hash
Un hash como SHA-256 produce una huella de 256 bits. Cambiar un solo bit del archivo cambia el resultado por completo.
Sirve para verificar integridad, no para ocultar información.

## 3. Contraseñas
Nunca se guardan: se almacena el resultado de un algoritmo de derivación lento y con sal, como Argon2id o bcrypt.
Un cifrado reversible no es una solución, porque quien robe la clave recupera todas las contraseñas.

## 4. Cifrado simétrico
AES-256 en modo GCM cifra y además autentica los datos: si alguien altera el archivo cifrado, el descifrado falla.

## 5. Firma digital
Se calcula el hash del documento y se firma con la clave privada. Cualquiera con la clave pública puede verificarla.
Esto da integridad, autenticación del emisor y no repudio.

## 6. Certificados y PKI
Una Autoridad Certificadora firma el certificado del servidor. El navegador confía en la CA, no en cada servidor.

## 7. Ejercicios
1. Calcula el SHA-256 de dos archivos que difieren en un carácter y compara los resultados.
2. Firma un texto con RSA-PSS y modifica un byte: ¿qué ocurre al verificar?
3. Explica por qué una contraseña cifrada con AES no cumple como almacenamiento seguro.
"""


def _apuntes_txt():
    return """APUNTES DE REDES SEGURAS - UNIDAD 4

TLS: protege una sesion entre cliente y servidor (cifrado, integridad, autenticacion del servidor).
SSH: administracion remota cifrada; se recomienda autenticacion por par de claves y usuario distinto de root.
IPSec: protege paquetes IP en la capa de red. Modo transporte (host a host) y modo tunel (gateway a gateway).
VPN de acceso remoto: autentica a una persona y le da acceso solo a los recursos de su rol.
VPN sitio a sitio: une dos redes; se autentican los gateways entre si.

Arquitectura de administracion recomendada:
Internet -> VPN -> red administrativa -> SSH -> servidor de aplicacion.

Preguntas de repaso:
- Que valida un cliente cuando recibe un certificado de servidor?
- Por que conectarse a la VPN no debe dar acceso a todo?
- Donde usarias IPSec en modo tunel?
"""


def _manual_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    paginas = [
        ("Manual de seguridad en aplicaciones web", ["Capitulo 1. Validacion de entradas",
            "Toda entrada es hostil hasta demostrar lo contrario: valida tipo, longitud y formato.",
            "Usa consultas parametrizadas para evitar inyeccion SQL.",
            "Escapa la salida HTML para evitar XSS."]),
        ("Capitulo 2. Sesiones y control de acceso", ["La sesion se guarda en el servidor; la cookie solo lleva un token aleatorio.",
            "Marca la cookie como HttpOnly, Secure y SameSite.", "Aplica privilegio minimo: cada rol ve solo lo necesario.",
            "Protege los formularios con tokens CSRF."]),
        ("Capitulo 3. Registro y errores", ["Registra autenticacion, autorizacion y operaciones importantes.",
            "No muestres trazas ni detalles internos al usuario.", "Los registros no deben contener contrasenas ni claves."]),
    ]
    for titulo, lineas in paginas:
        c.setFont("Helvetica-Bold", 16)
        c.drawString(60, 780, titulo)
        c.setFont("Helvetica", 11)
        y = 740
        for l in lineas:
            c.drawString(60, y, l)
            y -= 22
        c.showPage()
    c.save()
    return buf.getvalue()


def _infografia_png():
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (640, 400), (245, 247, 250))
    d = ImageDraw.Draw(img)
    cajas = [("CA local (raiz)", (200, 30, 440, 90), (31, 58, 95)), ("Certificado del servidor", (200, 160, 440, 220), (45, 110, 160)),
             ("Navegador del cliente", (200, 290, 440, 350), (29, 122, 70))]
    for texto, caja, color in cajas:
        d.rounded_rectangle(caja, radius=10, fill=color)
        d.text((caja[0] + 20, caja[1] + 22), texto, fill=(255, 255, 255))
    d.line((320, 90, 320, 160), fill=(60, 60, 60), width=3)
    d.line((320, 220, 320, 290), fill=(60, 60, 60), width=3)
    d.text((335, 118), "firma", fill=(60, 60, 60))
    d.text((335, 248), "valida la cadena", fill=(60, 60, 60))
    for i in range(0, 640, 20):                    # trama de fondo para que la imagen tenga textura (mejor para LSB)
        d.line((i, 0, i + 40, 400), fill=(236 - i % 9, 240, 247 - i % 7), width=1)
    d.text((20, 20), "Cadena de confianza TLS", fill=(31, 58, 95))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


PRODUCTOS_DEMO = [  # (nombre, descripción, precio centavos, nombre de archivo, generador)
    ("Guía práctica de criptografía aplicada", "Libro electrónico en Markdown: servicios de seguridad, hash, contraseñas, AES, firma digital y PKI.", 14900, "guia_criptografia.md", lambda: _libro_md().encode()),
    ("Apuntes de redes seguras", "Apuntes de TLS, SSH, IPSec y VPN con preguntas de repaso.", 8900, "apuntes_redes_seguras.txt", lambda: _apuntes_txt().encode()),
    ("Manual de seguridad en aplicaciones web", "Manual en PDF: validación, sesiones, control de acceso, registro y errores.", 19900, "manual_seguridad_web.pdf", _manual_pdf),
    ("Infografía: cadena de confianza TLS", "Infografía en PNG lista para imprimir sobre CA, certificado y validación.", 4900, "infografia_tls.png", _infografia_png),
]


def _todos():
    """Los 4 productos originales (ids 1-4, los usan las pruebas) + el catálogo ampliado."""
    from . import catalogo_demo as cd
    for nombre, desc, precio, archivo, gen in PRODUCTOS_DEMO:
        cat, puntos = cd.ORIGINALES[archivo]
        yield nombre, desc, precio, archivo, cat, puntos, gen
    for nombre, desc, precio, archivo, cat, puntos, secciones in cd.PRODUCTOS:
        yield nombre, desc, precio, archivo, cat, puntos, (lambda n=nombre, d=desc, a=archivo, c=cat, s=secciones: cd.generar(n, d, a, c, s))


def sembrar_productos():
    """Idempotente: agrega solo los productos que falten (sirve para actualizar una instalación existente)."""
    con = get_db()
    for nombre, desc, precio, archivo, cat, puntos, gen in _todos():
        existente = con.execute("SELECT id, highlights FROM products WHERE download_name = ?", (archivo,)).fetchone()
        if existente:
            if not existente["highlights"]:                  # BD de la versión anterior: se completa categoría y puntos
                con.execute("UPDATE products SET category = ?, highlights = ? WHERE id = ?", (cat, "\n".join(puntos), existente["id"]))
            continue
        datos = gen()
        interno = secrets.token_hex(16) + ".enc"
        sha = servicios.guardar_producto_cifrado(datos, interno)
        con.execute("INSERT INTO products(name, description, price_cents, file_name, download_name, file_type, file_hash, status, "
                    "created_at, category, highlights) VALUES(?,?,?,?,?,?,?,'ACTIVO',?,?,?)",
                    (nombre, desc, precio, interno, archivo, fingerprint.tipo_de(archivo), sha, ahora(), cat, "\n".join(puntos)))
    con.commit()
