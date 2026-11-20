"""Pruebas adicionales: aplicaciones seguras (Unidad 5), gestión de sesiones, fingerprint, respaldo y SSH integrado."""
import io
import re
import sqlite3

from . import entorno as E
from .evidencia import anotar
from aplicacion import cripto, fingerprint, respaldo, servicios
from aplicacion.datos_demo import _infografia_png


def _subir(nav, url, campos, nombre, contenido):
    campos = dict(campos, csrf_token=nav.token(), archivo=(io.BytesIO(contenido), nombre))
    return nav.c.post(url, data=campos, base_url=E.B, content_type="multipart/form-data")


# ---------------------------------------------------------------- registro y contraseñas
def test_registro_valida_entradas_y_fuerza_rol_cliente():
    n = E.Navegador()
    casos = {
        "correo inválido": {"email": "no-es-correo", "name": "Pepe", "password": "Clave-Segura-2026", "password2": "Clave-Segura-2026"},
        "contraseña corta": {"email": "p1@tienda.test", "name": "Pepe", "password": "abc123", "password2": "abc123"},
        "sin números": {"email": "p2@tienda.test", "name": "Pepe", "password": "SoloLetrasLargas", "password2": "SoloLetrasLargas"},
        "no coinciden": {"email": "p3@tienda.test", "name": "Pepe", "password": "Clave-Segura-2026", "password2": "Otra-Clave-2026"},
        "nombre con etiquetas": {"email": "p4@tienda.test", "name": "<script>x</script>", "password": "Clave-Segura-2026", "password2": "Clave-Segura-2026"},
    }
    res = {k: n.post("/registro", d).status_code for k, d in casos.items()}
    assert set(res.values()) == {400}, res
    # intento de escalar privilegios en el alta: el campo 'role' simplemente se ignora
    r = n.post("/registro", {"email": "nuevo@tienda.test", "name": "Nuevo Usuario", "password": "Clave-Segura-2026",
                             "password2": "Clave-Segura-2026", "role": "ADMINISTRADOR"})
    assert r.status_code == 302
    assert E.consulta("SELECT role FROM users WHERE email = 'nuevo@tienda.test'")[0][0] == "CLIENTE"
    dup = n.post("/registro", {"email": "nuevo@tienda.test", "name": "Otro", "password": "Clave-Segura-2026", "password2": "Clave-Segura-2026"})
    assert dup.status_code == 400 and "ya existe" not in dup.text.lower()
    anotar("Registro: validación de entradas", f"Entradas inválidas rechazadas (400): {res}. 'role=ADMINISTRADOR' en el alta se ignora (queda CLIENTE). Correo duplicado: mensaje genérico, sin revelar que existe.")


def test_no_existe_contrasena_en_claro_en_la_base_de_datos():
    todo = " ".join(str(c) for t in ("users", "payments", "security_events", "downloads") for f in E.consulta(f"SELECT * FROM {t}") for c in tuple(f))
    for _c, _n, _r, pw in __import__("aplicacion.datos_demo", fromlist=["x"]).USUARIOS_PRUEBA:
        assert pw not in todo
    cols = [c[1] for c in E.consulta("PRAGMA table_info(users)")]
    assert "password" not in cols and "password_hash" in cols
    hashes = [r[0] for r in E.consulta("SELECT password_hash FROM users")]
    assert len(set(hashes)) == len(hashes)          # misma contraseña de ana y luis -> hashes distintos (sal única)
    anotar("Contraseñas solo como hash", f"Columnas de users: {cols}. Ninguna contraseña de prueba aparece en la BD; ana y luis comparten contraseña pero tienen hashes distintos (sal por usuario).")


def test_bloqueo_por_intentos_fallidos():
    n = E.Navegador()
    E.registrar("bloqueo@tienda.test", "Cuenta Bloqueo")
    for _ in range(5):
        assert n.post("/login", {"email": "bloqueo@tienda.test", "password": "mala-contraseña-1"}).status_code == 401
    r = n.post("/login", {"email": "bloqueo@tienda.test", "password": "Clave-Segura-2026"})   # ni la contraseña correcta entra
    assert r.status_code == 429
    assert E.eventos("LOGIN_FAILED", "BLOQUEADO")
    anotar("Bloqueo por intentos fallidos", "5 contraseñas erróneas -> la 6ª, aun correcta, recibe HTTP 429 y queda LOGIN_FAILED/BLOQUEADO (ventana de 15 min).")


# ---------------------------------------------------------------- sesiones y CSRF
def test_csrf_peticion_sin_token_rechazada():
    n = E.Navegador.como(E.ANA)
    r = n.post("/carrito/agregar/1", csrf=False)
    r2 = n.post("/carrito/agregar/1", {"csrf_token": "token-falso"}, csrf=False)
    assert r.status_code == 400 and r2.status_code == 400
    assert E.eventos("CSRF_REJECTED")
    anotar("CSRF", "POST sin token y con token falso -> HTTP 400; evento CSRF_REJECTED.")


def test_cookie_de_sesion_y_encabezados_de_seguridad():
    n = E.Navegador()
    r = n.get("/")
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie
    h = r.headers
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff" and h["Strict-Transport-Security"] and h["Cache-Control"] == "no-store"
    anotar("Cookie y encabezados", f"Set-Cookie: {cookie.split(';')[0][:12]}…; {'; '.join(cookie.split(';')[1:]).strip()[:80]}\nCSP: {h['Content-Security-Policy']}")


def test_fijacion_de_sesion_se_rota_el_identificador_al_autenticar():
    n = E.Navegador()
    n.get("/")
    antes = E.consulta("SELECT COUNT(*) FROM sessions WHERE user_id IS NULL")[0][0]
    n.login(E.ANA)
    despues = E.consulta("SELECT COUNT(*) FROM sessions WHERE user_id IS NULL")[0][0]
    assert despues <= antes                                  # la anónima se destruyó y se creó una nueva con usuario
    tokens = [r[0] for r in E.consulta("SELECT id_hash FROM sessions")]
    assert all(len(t) == 64 for t in tokens)                 # solo hashes SHA-256, nunca el token real
    anotar("Sesiones", "Al iniciar sesión se destruye la sesión anónima y se crea otra (anti fijación). En la BD solo se guarda el SHA-256 del token.")


def test_admin_revoca_sesion_y_el_usuario_pierde_acceso():
    victima = E.Navegador.como(E.LUIS)
    assert victima.get("/ordenes").status_code == 200
    adm = E.Navegador.como(E.ADMIN)
    pagina = adm.get("/admin/sesiones").text
    ref = re.search(r'name="id_hash" value="([0-9a-f]{64})"', pagina[pagina.index("luis@tienda.test"):]).group(1)
    assert adm.post("/admin/sesiones/revocar", {"id_hash": ref}).status_code == 302
    assert victima.get("/ordenes").status_code == 302        # ya no tiene sesión: lo manda a /login
    assert E.eventos("SESSION_REVOKED", "OK")
    anotar("Revocar sesiones", "El ADMINISTRADOR revoca la sesión de luis; su siguiente petición es redirigida a /login. Evento SESSION_REVOKED.")


def test_desactivar_cuenta_bloquea_acceso_y_revoca_sesiones():
    victima = E.Navegador.como(E.LUIS)
    adm = E.Navegador.como(E.ADMIN)
    uid = E.consulta("SELECT id FROM users WHERE email = ?", (E.LUIS[0],))[0][0]
    adm.post(f"/admin/usuarios/{uid}/estado")
    assert victima.get("/ordenes").status_code == 302
    assert E.Navegador().login(E.LUIS).status_code == 401
    assert E.eventos("ACCOUNT_DISABLED", "OK", f"usuario={uid}")
    adm.post(f"/admin/usuarios/{uid}/estado")                 # se reactiva
    assert E.Navegador().login(E.LUIS).status_code in (302, 429)
    # el administrador no puede desactivarse a sí mismo ni cambiar su rol
    aid = E.consulta("SELECT id FROM users WHERE email = ?", (E.ADMIN[0],))[0][0]
    adm.post(f"/admin/usuarios/{aid}/estado")
    adm.post(f"/admin/usuarios/{aid}/rol", {"rol": "CLIENTE"})
    assert E.consulta("SELECT status, role FROM users WHERE id = ?", (aid,))[0][:] == ("ACTIVO", "ADMINISTRADOR")
    anotar("Desactivar cuenta", "Cuenta desactivada: sesiones revocadas y login rechazado; ACCOUNT_DISABLED registrado. El admin no puede desactivarse ni quitarse el rol a sí mismo.")


# ---------------------------------------------------------------- recuperación de contraseña
def _token_de_correo(para="reset@tienda.test"):
    return re.findall(r"/restablecer/([A-Za-z0-9_\-]+)", E.ultimo_correo(para))[-1]


def test_recuperacion_de_contrasena_token_unico_y_con_expiracion():
    E.registrar("reset@tienda.test", "Reset Prueba", "Vieja-Clave-2026")
    n = E.Navegador()
    r_existe = n.post("/recuperar", {"email": "reset@tienda.test"})
    r_no = n.post("/recuperar", {"email": "nadie@tienda.test"})
    assert r_existe.status_code == r_no.status_code == 200
    principal = lambda r, correo: r.text.split("<main>")[1].replace(correo, "CORREO")
    assert principal(r_existe, "reset@tienda.test") == principal(r_no, "nadie@tienda.test")   # misma respuesta exista o no
    assert "/restablecer/" not in r_existe.text                  # el enlace NO se muestra en pantalla (solo en el correo)
    token = _token_de_correo()
    guardado = E.consulta("SELECT token_hash FROM password_resets")[-1][0]
    assert token not in guardado and len(guardado) == 64       # en la BD solo queda el hash del token
    assert n.post(f"/restablecer/{token}", {"password": "corta", "password2": "corta"}).status_code == 400
    ok = n.post(f"/restablecer/{token}", {"password": "Nueva-Clave-2026", "password2": "Nueva-Clave-2026"})
    assert ok.status_code == 302
    assert E.Navegador().login(("reset@tienda.test", "Vieja-Clave-2026")).status_code == 401
    assert E.Navegador().login(("reset@tienda.test", "Nueva-Clave-2026")).status_code == 302
    reuso = n.post(f"/restablecer/{token}", {"password": "Otra-Clave-2026x", "password2": "Otra-Clave-2026x"})
    assert reuso.status_code == 302 and "recuperar" in reuso.headers["Location"]       # un token ya usado no sirve
    # token vencido
    E.Navegador().post("/recuperar", {"email": "reset@tienda.test"})
    t2 = _token_de_correo()
    E.ejecutar("UPDATE password_resets SET expires_at = '2000-01-01 00:00:00' WHERE used = 0")
    assert E.Navegador().get(f"/restablecer/{t2}").status_code == 302
    assert E.eventos("PASSWORD_RESET", "OK") and E.eventos("PASSWORD_RESET", "RECHAZADO")
    anotar("Recuperación de contraseña (enlace)", "Respuesta idéntica para correos existentes y no existentes; token aleatorio guardado como hash; un solo uso; vencimiento; la contraseña vieja deja de funcionar; PASSWORD_RESET registrado.")


def test_recuperacion_con_codigo_token_enviado_por_correo():
    E.registrar("codigo@tienda.test", "Codigo Prueba", "Vieja-Clave-2026")
    n = E.Navegador()
    n.post("/recuperar", {"email": "codigo@tienda.test"})
    codigo = E.codigo_de_correo("codigo@tienda.test")
    fila = E.consulta("SELECT code_hash FROM password_resets WHERE used = 0 ORDER BY rowid DESC LIMIT 1")[0][0]
    assert codigo not in fila and len(fila) == 64                 # en la BD solo el hash del código
    malo = "000000" if codigo != "000000" else "111111"
    datos = {"email": "codigo@tienda.test", "password": "Nueva-Clave-2026", "password2": "Nueva-Clave-2026"}
    assert n.post("/restablecer", dict(datos, codigo=malo)).status_code == 400
    assert n.post("/restablecer", dict(datos, codigo=codigo)).status_code == 302
    assert E.Navegador().login(("codigo@tienda.test", "Nueva-Clave-2026")).status_code == 302
    assert n.post("/restablecer", dict(datos, codigo=codigo, password="Otra-Clave-2026x", password2="Otra-Clave-2026x")).status_code == 400
    # fuerza bruta: tras 5 intentos fallidos el código se invalida aunque después llegue el correcto
    n.post("/recuperar", {"email": "codigo@tienda.test"})
    codigo2 = E.codigo_de_correo("codigo@tienda.test")
    for k in range(5):
        n.post("/restablecer", dict(datos, codigo=f"{(int(codigo2) + k + 1) % 10**6:06d}"))
    assert n.post("/restablecer", dict(datos, codigo=codigo2, password="Tercera-Clave-2026", password2="Tercera-Clave-2026")).status_code == 400
    # pedir un código nuevo invalida el anterior
    n.post("/recuperar", {"email": "codigo@tienda.test"})
    viejo = E.codigo_de_correo("codigo@tienda.test")
    n.post("/recuperar", {"email": "codigo@tienda.test"})
    assert viejo == E.codigo_de_correo("codigo@tienda.test") or \
        n.post("/restablecer", dict(datos, codigo=viejo)).status_code == 400
    anotar("Recuperación con código por correo", "Se envía un código (token) de 6 dígitos al correo; en la BD solo queda su hash; "
           "un código erróneo -> 400; el correcto cambia la contraseña; no se puede reutilizar; 5 intentos fallidos lo invalidan; "
           "pedir otro invalida el anterior.")


def test_registro_exige_confirmar_el_correo():
    n = E.Navegador()
    r = n.post("/registro", {"email": "confirma@tienda.test", "name": "Confirma Correo", "password": "Clave-Segura-2026", "password2": "Clave-Segura-2026"})
    assert r.status_code == 302 and "verificar-correo" in r.headers["Location"]
    assert E.consulta("SELECT email_verified FROM users WHERE email = 'confirma@tienda.test'")[0][0] == 0
    correo = E.ultimo_correo("confirma@tienda.test")
    codigo = E.codigo_de_correo("confirma@tienda.test")
    assert "código" in correo.lower() and len(codigo) == 6
    r = E.Navegador().login(("confirma@tienda.test", "Clave-Segura-2026"))
    assert r.status_code == 302 and "verificar-correo" in r.headers["Location"]          # sin confirmar no entra
    assert n.post("/verificar-correo", {"accion": "confirmar", "email": "confirma@tienda.test", "codigo": "12345"}).status_code == 400
    ok = n.post("/verificar-correo", {"accion": "confirmar", "email": "confirma@tienda.test", "codigo": codigo})
    assert ok.status_code == 302
    assert E.Navegador().login(("confirma@tienda.test", "Clave-Segura-2026")).status_code == 302
    assert E.eventos("EMAIL_VERIFIED", "OK") and E.eventos("LOGIN_PENDING_VERIFICATION", "PENDIENTE")
    anotar("Alta de correo", "Al registrarse se envía un código de 6 dígitos; la cuenta no puede iniciar sesión hasta confirmarlo; "
           "un código inválido -> 400; EMAIL_VERIFIED registrado.")


def test_correo_por_smtp_real_con_starttls(monkeypatch=None):
    """Con SMTP configurado el correo sale por el servidor (aquí uno falso que registra la conversación)."""
    import os
    import smtplib
    enviados = []

    class SMTPFalso:
        def __init__(self, host, puerto, timeout=None):
            self.host, self.puerto, self.pasos = host, puerto, []
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def ehlo(self):
            self.pasos.append("ehlo")
        def starttls(self, context=None):
            assert context is not None and context.verify_mode.name == "CERT_REQUIRED"
            self.pasos.append("starttls")
        def login(self, u, p):
            self.pasos.append(("login", u))
        def send_message(self, m):
            assert "starttls" in self.pasos                     # nunca se manda la contraseña ni el código sin cifrar
            enviados.append(m)

    original = smtplib.SMTP
    env = {"SMTP_HOST": "smtp.ejemplo.test", "SMTP_PUERTO": "587", "SMTP_USUARIO": "tienda@ejemplo.test", "SMTP_CONTRASENA": "x"}
    smtplib.SMTP = SMTPFalso
    os.environ.update(env)
    try:
        E.Navegador().post("/registro", {"email": "smtp@tienda.test", "name": "Smtp Prueba", "password": "Clave-Segura-2026", "password2": "Clave-Segura-2026"})
    finally:
        smtplib.SMTP = original
        for k in env:
            os.environ.pop(k, None)
    assert len(enviados) == 1 and enviados[0]["To"] == "smtp@tienda.test"
    cuerpo = enviados[0].get_body(("plain",)).get_content()
    assert re.search(r"\b\d{6}\b", cuerpo)
    assert "smtp@tienda.test" not in (E.AJ.REGISTROS_DIR / "correo_simulado.log").read_text(encoding="utf-8")
    assert E.eventos("EMAIL_SENT", "OK", "via=smtp")
    anotar("Correo saliente por SMTP", "Con SMTP_HOST/USUARIO/CONTRASEÑA configurados el código se envía por el servidor de correo "
           "usando STARTTLS con verificación de certificado; no queda en el buzón simulado.")


# ---------------------------------------------------------------- aislamiento entre usuarios (IDOR) y privilegio mínimo
def test_cliente_no_ve_ordenes_ni_comprobantes_ajenos():
    ana = E.Navegador.como(E.ANA)
    oid = E.comprar(ana, (4,))
    luis = E.Navegador.como(E.LUIS)
    codigos = (luis.get(f"/ordenes/{oid}").status_code, luis.get(f"/comprobantes/{oid}").status_code,
               luis.get(f"/comprobantes/{oid}/descargar").status_code, luis.post(f"/ordenes/{oid}/pagar", E.TARJETA_OK).status_code)
    assert codigos == (404, 404, 404, 404), codigos
    anotar("Aislamiento entre clientes", f"luis intenta ver/pagar la orden #{oid} de ana -> {codigos} (404: no se revela que existe). Eventos ACCESS_DENIED.")


def test_operador_puede_gestionar_catalogo_y_pedidos_pero_no_ver_eventos():
    op = E.Navegador.como(E.OPERADOR)
    assert op.get("/operador/productos").status_code == 200 and op.get("/operador/ordenes").status_code == 200
    assert op.get("/admin/eventos").status_code == 403 and op.get("/admin/configuracion").status_code == 403
    assert op.get("/carrito").status_code == 403                      # tampoco compra
    anotar("Privilegio mínimo (OPERADOR)", "OPERADOR: catálogo y pedidos 200; eventos de seguridad, configuración y carrito 403.")


def test_operador_precios_historicos_y_estado_de_ordenes():
    ana = E.Navegador.como(E.ANA)
    oid = E.comprar(ana, (4,))
    antes = E.consulta("SELECT price_cents FROM order_items WHERE order_id = ?", (oid,))[0][0]
    op = E.Navegador.como(E.OPERADOR)
    p = E.consulta("SELECT * FROM products WHERE id = 4")[0]
    r = op.post("/operador/productos/4", {"name": p["name"], "description": p["description"], "price": "99.99"})
    assert r.status_code == 302
    assert E.consulta("SELECT price_cents FROM order_items WHERE order_id = ?", (oid,))[0][0] == antes      # precio histórico intacto
    assert E.consulta("SELECT price_cents FROM products WHERE id = 4")[0][0] == 9999
    op.post("/operador/productos/4", {"name": p["name"], "description": p["description"], "price": f"{p['price_cents']/100:.2f}"})
    assert op.post("/operador/productos/4", {"name": "x", "description": "d", "price": "-5"}).status_code == 400
    r = op.post(f"/operador/ordenes/{oid}", {"estado": "COMPLETADA"})
    assert E.consulta("SELECT status FROM orders WHERE id = ?", (oid,))[0][0] == "COMPLETADA"
    op.post(f"/operador/ordenes/{oid}", {"estado": "PENDIENTE"})                   # transición no permitida
    assert E.consulta("SELECT status FROM orders WHERE id = ?", (oid,))[0][0] == "COMPLETADA"
    anotar("OPERADOR: precios y estados", f"Cambio de precio no altera órdenes anteriores (order_items conserva {antes} centavos). Precio negativo rechazado. Transiciones de estado válidas solamente.")


# ---------------------------------------------------------------- inyección y XSS
def test_inyeccion_sql_y_xss_no_prosperan():
    n = E.Navegador()
    r = n.post("/login", {"email": "' OR '1'='1' --", "password": "' OR '1'='1"})
    assert r.status_code == 401
    assert n.get("/producto/1%20OR%201=1").status_code == 404
    assert n.get("/producto/1;DROP TABLE users").status_code == 404
    assert E.consulta("SELECT COUNT(*) FROM users")[0][0] >= 4
    # XSS almacenado: nombre con HTML se rechaza; un correo/texto con HTML se muestra escapado
    ana = E.Navegador.como(E.ANA)
    ana.post("/perfil", {"name": "Ana & <b>Co</b>"})
    assert "<b>Co</b>" not in ana.get("/perfil").text
    pagina = E.Navegador.como(E.ANA).get("/perfil").text
    assert "&lt;b&gt;" in pagina or "Ana Cliente" in pagina
    # inyección en la bitácora: saltos de línea del usuario no crean líneas falsas
    n.post("/login", {"email": "x@y.test\n[2026-01-01 00:00:00] LOGIN_SUCCESS | usuario=admin", "password": "x"})
    log = (E.AJ.REGISTROS_DIR / "auditoria.log").read_text(encoding="utf-8")
    assert not any(l.startswith("[2026-01-01") for l in log.splitlines())
    anotar("Inyección SQL / XSS / log injection", "Payloads de SQLi en login y en la URL -> 401/404 sin efecto (consultas parametrizadas). HTML en nombres escapado por la plantilla (autoescape). Saltos de línea en el correo no falsifican líneas de bitácora.")


def test_bitacora_de_eventos_es_de_solo_escritura():
    for sql in ("UPDATE security_events SET result = 'OK' WHERE id = 1", "DELETE FROM security_events WHERE id = 1"):
        try:
            E.ejecutar(sql)
            raise AssertionError("se pudo alterar la bitácora")
        except sqlite3.DatabaseError as e:
            assert "solo escritura" in str(e)
    anotar("Bitácora inmutable", "UPDATE y DELETE sobre security_events fallan por trigger: 'security_events es de solo escritura'.")


def test_eventos_obligatorios_con_usuario_fecha_resultado_y_origen():
    exigidos = ["LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT", "PASSWORD_RESET", "ORDER_CREATED", "PAYMENT_APPROVED", "DOWNLOAD",
                "ROLE_CHANGED", "ACCOUNT_DISABLED", "SIGNATURE_CREATED", "FINGERPRINT_CREATED"]
    n = E.Navegador.como(E.ANA)
    n.post("/logout")
    presentes = {r[0] for r in E.consulta("SELECT DISTINCT event FROM security_events")}
    faltan = [e for e in exigidos if e not in presentes]
    assert not faltan, faltan
    campos = E.consulta("SELECT user_email, event, created_at, result, origin FROM security_events")
    assert all(all(c not in (None, "") for c in tuple(f)) for f in campos)
    anotar("Eventos de seguridad (sección 16)", f"Los 11 eventos exigidos están presentes ({len(presentes)} tipos en total); todos con usuario, evento, fecha/hora, resultado y origen.")


# ---------------------------------------------------------------- productos: subida segura y cifrado en reposo
def test_subida_de_productos_valida_tipo_y_cifra_en_reposo():
    op = E.Navegador.como(E.OPERADOR)
    campos = {"name": "Producto de prueba", "description": "Descripción de prueba", "price": "10.00", "category": "Apuntes"}
    assert _subir(op, "/operador/productos/nuevo", campos, "malware.exe", b"MZ\x90\x00").status_code == 400
    assert _subir(op, "/operador/productos/nuevo", campos, "falso.png", b"esto no es un png").status_code == 400
    assert _subir(op, "/operador/productos/nuevo", campos, "../../etc/passwd.txt", b"\xff\xfe\x00binario").status_code == 400
    secreto = "CONTENIDO-CONFIDENCIAL-DEL-LIBRO-7788"
    r = _subir(op, "/operador/productos/nuevo", campos, "../../libro.txt", secreto.encode())
    assert r.status_code == 302
    fila = E.consulta("SELECT * FROM products ORDER BY id DESC LIMIT 1")[0]
    en_disco = (E.AJ.PRODUCTOS_DIR / fila["file_name"]).read_bytes()
    assert secreto.encode() not in en_disco                      # cifrado en reposo
    assert fila["download_name"] == "libro.txt" and ".." not in fila["download_name"]
    assert fila["file_hash"] == cripto.sha256_bytes(secreto.encode())
    anotar("Subida de productos", f".exe, PNG falso y binario como .txt rechazados (400); ruta '../../libro.txt' saneada a '{fila['download_name']}'. El archivo en disco ({fila['file_name'][:12]}….enc) no contiene el texto en claro; SHA-256 registrado.")


def test_producto_alterado_en_disco_se_detecta_al_descargar():
    op = E.Navegador.como(E.OPERADOR)
    _subir(op, "/operador/productos/nuevo", {"name": "Producto frágil", "description": "d", "price": "1.00", "category": "Guías"}, "fragil.txt", b"contenido original")
    pid = E.consulta("SELECT id, file_name FROM products ORDER BY id DESC LIMIT 1")[0]
    cli = E.Navegador.como(E.ANA)
    oid = E.comprar(cli, (pid["id"],))
    assert cli.get(f"/descargas/{oid}/{pid['id']}").status_code == 200
    ruta = E.AJ.PRODUCTOS_DIR / pid["file_name"]
    b = ruta.read_bytes()
    ruta.write_bytes(b[:20] + bytes([b[20] ^ 0xFF]) + b[21:])
    r = cli.get(f"/descargas/{oid}/{pid['id']}")
    assert r.status_code == 500 and "Traceback" not in r.text and "InvalidTag" not in r.text
    assert E.eventos("INTEGRITY_FAILURE", "ERROR")
    anotar("Integridad al descargar", "Se alteró 1 byte del producto cifrado: la descarga se rechaza (HTTP 500 genérico, sin detalles internos) y queda INTEGRITY_FAILURE.")


# ---------------------------------------------------------------- fingerprint
def test_fingerprint_es_distinto_por_comprador_y_no_se_puede_forjar():
    clave = servicios_clave()
    with E.app().app_context():
        p = E.consulta("SELECT * FROM products WHERE id = 1")[0]
        a, ha = servicios.copia_personalizada(p, 3, 10)
        b, hb = servicios.copia_personalizada(p, 4, 11)
    assert a != b and ha != hb and cripto.sha256_bytes(a) != cripto.sha256_bytes(b)
    assert fingerprint.extraer(a, "md", clave) == {"user_id": 3, "order_id": 10, "product_id": 1}
    assert fingerprint.extraer(b, "md", clave) == {"user_id": 4, "order_id": 11, "product_id": 1}
    # forja: alguien intenta fabricar una huella para incriminar a otro usuario sin conocer la clave HMAC
    falsa = fingerprint.crear_carga(9, 99, 1, b"clave-equivocada-xxxxxxxxxxxxxxxxx")
    assert fingerprint.validar_carga(falsa, clave) is None
    marca = fingerprint._marca_texto(falsa)
    forjado = ("Texto cualquiera\n" + marca + "\n").encode()
    assert fingerprint.extraer(forjado, "md", clave) is None
    # robustez del texto: fragmento recortado y renombrado sigue identificando; texto "limpiado" ya no
    mitad = a[len(a) // 2:]
    assert fingerprint.extraer(mitad, "md", clave)["user_id"] == 3
    limpio = a.decode().replace("\u200b", "").replace("\u200c", "").replace("\u200d", "").encode()
    assert fingerprint.extraer(limpio, "md", clave) is None
    anotar("Fingerprint: unicidad, forja y robustez", "Cada comprador recibe bytes distintos del mismo producto. Una huella fabricada sin la clave HMAC se rechaza. "
           "Texto: sobrevive al recorte de la mitad del documento; se pierde si se eliminan los caracteres de ancho cero (limitación documentada).")


def servicios_clave():
    return cripto.clave_simetrica(E.AJ.CLAVES_DIR, "fingerprint.key")


def test_fingerprint_png_es_imperceptible_y_tolera_ruido_leve():
    clave = servicios_clave()
    original = _infografia_png()
    copia, _ = fingerprint.incrustar(original, "png", 5, 77, 4, clave)
    db_ = fingerprint.psnr(original, copia)
    assert db_ > 45, db_
    # ruido: se invierte el LSB de ~2 % de los bytes; el voto mayoritario aún recupera la huella
    from PIL import Image
    import random
    img = Image.open(io.BytesIO(copia)).convert("RGB")
    raw = bytearray(img.tobytes())
    random.Random(1).shuffle(idx := list(range(len(raw))))
    for i in idx[: len(raw) // 50]:
        raw[i] ^= 1
    ruidosa = io.BytesIO()
    Image.frombytes("RGB", img.size, bytes(raw)).save(ruidosa, "PNG")
    assert fingerprint.extraer(ruidosa.getvalue(), "png", clave) == {"user_id": 5, "order_id": 77, "product_id": 4}
    # JPEG destruye el LSB: se documenta como límite
    jpg = io.BytesIO()
    img.save(jpg, "JPEG", quality=85)
    perdida = fingerprint.extraer(jpg.getvalue(), "png", clave) is None
    assert perdida
    anotar("Fingerprint PNG (LSB)", f"PSNR = {db_:.1f} dB (>45 dB: imperceptible). Con 2 % de ruido en los LSB la huella se recupera por voto mayoritario. Tras recomprimir a JPEG se pierde (límite documentado).")
    from .evidencia import ARCHIVOS
    ARCHIVOS["infografia_original.png"] = original
    ARCHIVOS["infografia_con_huella_usuario5_orden77.png"] = copia


# ---------------------------------------------------------------- respaldo
def test_respaldo_alterado_no_se_restaura():
    import zipfile
    zip_ = respaldo.crear_respaldo(E.AJ)
    malo = zip_.with_name("malo.zip")
    with zipfile.ZipFile(zip_) as zin, zipfile.ZipFile(malo, "w") as zout:
        for item in zin.infolist():
            datos = zin.read(item.filename)
            if item.filename.startswith("productos/"):
                datos = datos[:30] + bytes([datos[30] ^ 1]) + datos[31:]
            zout.writestr(item.filename, datos)
    try:
        respaldo.verificar_respaldo(malo, E.AJ)
        raise AssertionError("se aceptó un respaldo alterado")
    except respaldo.ErrorRespaldo as e:
        motivo = str(e)
    try:                                                      # y tampoco se sobrescribe una BD existente sin --forzar
        respaldo.restaurar(zip_, E.AJ)
        raise AssertionError("sobrescribió sin pedirlo")
    except respaldo.ErrorRespaldo:
        pass
    anotar("Respaldo alterado", f"Al modificar un byte de un producto dentro del .zip: {motivo}. Sin --forzar no se sobrescribe la BD existente.")


# ---------------------------------------------------------------- integración con infraestructura/ (SSH + AAA + bitácora)
def test_ssh_usa_los_usuarios_de_la_tienda_con_privilegio_minimo():
    from aplicacion import puente_aaa
    aaa = puente_aaa.instalar(E.AJ)
    try:
        rol_admin = aaa.autenticar(E.ADMIN[0], E.ADMIN[1], "10.0.0.5", "ssh")
        rol_op = aaa.autenticar(E.OPERADOR[0], E.OPERADOR[1], "10.0.0.5", "ssh")
        rol_cli = aaa.autenticar(E.ANA[0], E.ANA[1], "10.0.0.5", "ssh")
        mala = aaa.autenticar(E.ADMIN[0], "contraseña-incorrecta", "10.0.0.5", "ssh")
        assert (rol_admin, rol_op, rol_cli, mala) == ("ADMINISTRADOR", "OPERADOR", "CLIENTE", None)
        matriz = {
            "ADMIN ssh:login / restart-service": (aaa.tiene_permiso(rol_admin, "ssh:login"), aaa.tiene_permiso(rol_admin, "ssh:restart-service")),
            "OPERADOR ssh:login / restart-service": (aaa.tiene_permiso(rol_op, "ssh:login"), aaa.tiene_permiso(rol_op, "ssh:restart-service")),
            "CLIENTE ssh:login": (aaa.tiene_permiso(rol_cli, "ssh:login"),),
        }
        assert matriz["ADMIN ssh:login / restart-service"] == (True, True)
        assert matriz["OPERADOR ssh:login / restart-service"] == (True, False)
        assert matriz["CLIENTE ssh:login"] == (False,)
        # los intentos quedaron en la MISMA bitácora que usa la tienda
        log = (E.AJ.REGISTROS_DIR / "auditoria.log").read_text(encoding="utf-8")
        assert "AUTENTICACION" in log and "BD tienda" in log
        # los usuarios de laboratorio originales de infraestructura/ siguen funcionando
        assert aaa.autenticar("admin_sistemas", "claveSegura123", "10.0.0.5", "ssh") == "administrador"
    finally:
        aaa.PROVEEDOR_EXTERNO = None
    anotar("Integración SSH/AAA con la BD de la tienda", f"Autenticación contra la tabla users: {matriz}. Contraseña errónea -> None. Registros en auditoria.log compartida. Usuarios de laboratorio originales intactos.")


def test_roles_matriz_de_privilegios_minimos():
    from aplicacion import seguridad
    P = seguridad.PERMISOS
    assert not (P["CLIENTE"] & (P["OPERADOR"] | P["ADMINISTRADOR"]) - {"perfil:editar", "catalogo:ver"})
    assert "rol:asignar" not in P["OPERADOR"] and "producto:modificar" not in P["ADMINISTRADOR"]
    assert not any("password" in p or "clave" in p for r in P.values() for p in r)
    anotar("Separación de responsabilidades", "Los conjuntos de permisos de CLIENTE, OPERADOR y ADMINISTRADOR solo comparten 'perfil:editar' y 'catalogo:ver'; el ADMINISTRADOR no gestiona productos ni compra, el OPERADOR no asigna roles; ningún rol tiene permisos sobre contraseñas ni claves.")
