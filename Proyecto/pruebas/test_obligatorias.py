"""Las 13 pruebas mínimas obligatorias del documento del proyecto (sección 19), en el mismo orden."""
import http.client
import io
import json
import ssl
import threading

from . import entorno as E
from .evidencia import ARCHIVOS, anotar
from aplicacion import cripto, fingerprint, respaldo, servicios


# ---------------------------------------------------------------- 1. Contraseña incorrecta
def test_01_contrasena_incorrecta_acceso_rechazado():
    n = E.Navegador()
    r = n.post("/login", {"email": E.ANA[0], "password": "ContraseñaEquivocada1"})
    assert r.status_code == 401
    assert n.get("/mis-productos").status_code == 302          # sigue sin sesión: lo manda a /login
    ev = E.eventos("LOGIN_FAILED", "RECHAZADO")
    assert any(e["user_email"] == E.ANA[0] for e in ev)
    h = E.consulta("SELECT password_hash FROM users WHERE email = ?", (E.ANA[0],))[0][0]
    assert E.ANA[1] not in h and (h.startswith("$argon2id$") or h.startswith("scrypt$"))
    anotar("01 Contraseña incorrecta", f"POST /login con contraseña errónea -> HTTP 401; LOGIN_FAILED registrado. "
           f"password_hash almacenado empieza con '{h[:14]}…' (nunca la contraseña).")


# ---------------------------------------------------------------- 2. CLIENTE intenta función administrativa
def test_02_cliente_funcion_administrativa_rechazada():
    n = E.Navegador.como(E.ANA)
    codigos = {u: n.get(u).status_code for u in ("/admin/usuarios", "/admin/eventos", "/admin/sesiones", "/operador/productos", "/operador/ordenes")}
    assert set(codigos.values()) == {403}, codigos
    assert E.eventos("ACCESS_DENIED", "DENEGADO", "usuario:consultar")
    anotar("02 CLIENTE -> función administrativa", "GET a rutas de ADMINISTRADOR/OPERADOR -> " + ", ".join(f"{u}: {c}" for u, c in codigos.items()) + ". Eventos ACCESS_DENIED registrados.")


# ---------------------------------------------------------------- 3. OPERADOR intenta cambiar roles
def test_03_operador_cambia_roles_rechazado():
    n = E.Navegador.como(E.OPERADOR)
    uid = E.consulta("SELECT id FROM users WHERE email = ?", (E.LUIS[0],))[0][0]
    r = n.post(f"/admin/usuarios/{uid}/rol", {"rol": "ADMINISTRADOR"})
    assert r.status_code == 403
    assert E.consulta("SELECT role FROM users WHERE id = ?", (uid,))[0][0] == "CLIENTE"
    assert n.get("/admin/usuarios").status_code == 403
    anotar("03 OPERADOR -> cambiar roles", f"POST /admin/usuarios/{uid}/rol (rol=ADMINISTRADOR) -> HTTP 403; el rol en la BD sigue siendo CLIENTE.")


# ---------------------------------------------------------------- 4. ADMINISTRADOR autorizado
def test_04_administrador_autorizado_operacion_permitida():
    n = E.Navegador.como(E.ADMIN)
    uid = E.consulta("SELECT id FROM users WHERE email = ?", (E.LUIS[0],))[0][0]
    assert n.get("/admin/usuarios").status_code == 200
    assert n.get("/admin/eventos").status_code == 200
    r = n.post(f"/admin/usuarios/{uid}/rol", {"rol": "OPERADOR"})
    assert r.status_code == 302 and E.consulta("SELECT role FROM users WHERE id = ?", (uid,))[0][0] == "OPERADOR"
    assert E.eventos("ROLE_CHANGED", "OK", f"usuario={uid}")
    n.post(f"/admin/usuarios/{uid}/rol", {"rol": "CLIENTE"})                     # se deja como estaba
    anotar("04 ADMINISTRADOR autorizado", "Consulta usuarios/eventos (200) y cambia el rol de un usuario CLIENTE->OPERADOR (302). Evento ROLE_CHANGED registrado; se revirtió.")


# ---------------------------------------------------------------- 5-6. TLS
def _servidor_tls(crt, key):
    from werkzeug.serving import make_server
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(E.AJ.CERTS_DIR / crt), str(E.AJ.CERTS_DIR / key))
    srv = make_server("127.0.0.1", 0, E.app(), ssl_context=ctx, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _https_get(puerto, ca):
    ctx = ssl.create_default_context(cafile=str(E.AJ.CERTS_DIR / ca)) if ca else ssl.create_default_context()
    con = http.client.HTTPSConnection("localhost", puerto, context=ctx, timeout=5)
    try:
        con.connect()                                     # aquí ocurre el handshake TLS y se valida el certificado
        version, cifrado = con.sock.version(), con.sock.cipher()[0]
        con.request("GET", "/")
        r = con.getresponse()
        return r.status, version, cifrado, r.getheader("Strict-Transport-Security")
    finally:
        con.close()


def test_05_tls_certificado_correcto_conexion_aceptada():
    srv = _servidor_tls("server.crt", "server.key")
    try:
        estado, version, cifrado, hsts = _https_get(srv.server_port, "ca.crt")
    finally:
        srv.shutdown()
    assert estado == 200 and version in ("TLSv1.2", "TLSv1.3") and hsts
    anotar("05 Certificado TLS correcto", f"Cliente que confía en la CA local (ca.crt) -> HTTP {estado} sobre {version} / {cifrado}; encabezado HSTS presente.")


def test_06_tls_certificado_no_confiable_conexion_rechazada():
    resultados = []
    for crt, key, ca, etiqueta in (("rogue_server.crt", "rogue_server.key", "ca.crt", "firmado por una CA falsa"),
                                   ("expired.crt", "expired.key", "ca.crt", "caducado"),
                                   ("wronghost.crt", "wronghost.key", "ca.crt", "emitido para otro nombre"),
                                   ("server.crt", "server.key", None, "legítimo pero el cliente NO confía en la CA local")):
        srv = _servidor_tls(crt, key)
        try:
            try:
                _https_get(srv.server_port, ca)
                raise AssertionError(f"se aceptó un certificado {etiqueta}")
            except ssl.SSLCertVerificationError as e:
                resultados.append(f"{etiqueta}: RECHAZADO ({e.verify_message})")
        finally:
            srv.shutdown()
    anotar("06 Certificado TLS no confiable", "\n".join(resultados))


# ---------------------------------------------------------------- 7-8. Firma digital
def test_07_comprobante_original_firma_valida():
    n = E.Navegador.como(E.ANA)
    oid = E.comprar(n, (1, 2))
    pagina = n.get(f"/comprobantes/{oid}")
    assert pagina.status_code == 200 and "FIRMA VÁLIDA" in pagina.text
    descarga = n.get(f"/comprobantes/{oid}/descargar")
    doc = json.loads(descarga.data)
    pub = cripto.cargar_publica(E.AJ.CLAVES_PUBLICAS_DIR)
    assert cripto.verificar(cripto.canonico(doc["comprobante"]), doc["firma"], pub)
    r = n.c.post("/verificar", data={"csrf_token": n.token(), "archivo": (io.BytesIO(descarga.data), "c.json")},
                 base_url=E.B, content_type="multipart/form-data")
    assert "Firma válida" in r.text
    assert E.eventos("SIGNATURE_CREATED", "OK", f"orden={oid}")
    anotar("07 Comprobante original", f"Orden #{oid}: la página muestra 'FIRMA VÁLIDA'; verificación externa con la clave pública (RSA-PSS/SHA-256) = True; "
           f"el cliente también la verifica subiendo el .json. key_id={doc['key_id']}")
    ARCHIVOS["comprobante_orden_valido.json"] = descarga.data


def test_08_comprobante_modificado_firma_invalida():
    n = E.Navegador.como(E.ANA)
    oid = E.comprar(n, (2,))
    original = json.loads(n.get(f"/comprobantes/{oid}/descargar").data)
    falso = json.loads(json.dumps(original))
    falso["comprobante"]["total_centavos"] = 1                   # el cliente intenta "abaratar" su comprobante
    pub = cripto.cargar_publica(E.AJ.CLAVES_PUBLICAS_DIR)
    assert not cripto.verificar(cripto.canonico(falso["comprobante"]), falso["firma"], pub)
    r = n.c.post("/verificar", data={"csrf_token": n.token(), "archivo": (io.BytesIO(json.dumps(falso).encode()), "c.json")},
                 base_url=E.B, content_type="multipart/form-data")
    assert "Firma inválida" in r.text
    # alteración directa en la BD: la página debe detectarla
    E.ejecutar("UPDATE receipts SET content = replace(content, '\"total_centavos\":8900', '\"total_centavos\":1') WHERE order_id = ?", (oid,))
    assert "FIRMA INVÁLIDA" in n.get(f"/comprobantes/{oid}").text
    anotar("08 Comprobante modificado", f"Orden #{oid}: se cambió el total (8900 -> 1) en el archivo y también en la BD -> la verificación devuelve FIRMA INVÁLIDA en ambos casos.")
    ARCHIVOS["comprobante_orden_modificado.json"] = json.dumps(falso, ensure_ascii=False, indent=2).encode()


# ---------------------------------------------------------------- 9. Fingerprint recuperable
def test_09_producto_descargado_fingerprint_recuperable():
    n = E.Navegador.como(E.ANA)
    uid = E.consulta("SELECT id FROM users WHERE email = ?", (E.ANA[0],))[0][0]
    oid = E.comprar(n, (1, 2, 3, 4))
    clave = servicios_clave()
    lineas = []
    for pid, tipo in ((1, "md"), (2, "txt"), (3, "pdf"), (4, "png")):
        r = n.get(f"/descargas/{oid}/{pid}")
        assert r.status_code == 200
        rec = fingerprint.extraer(r.data, tipo, clave)
        assert rec == {"user_id": uid, "order_id": oid, "product_id": pid}, (tipo, rec)
        lineas.append(f"  .{tipo}: huella recuperada -> usuario #{rec['user_id']}, orden #{rec['order_id']}, producto #{rec['product_id']}")
        COPIAS[tipo] = r.data
    # la herramienta del ADMINISTRADOR identifica a quien filtró una copia
    adm = E.Navegador.como(E.ADMIN)
    r = adm.c.post("/admin/fingerprint", data={"csrf_token": adm.token(), "archivo": (io.BytesIO(COPIAS["pdf"]), "filtrado.pdf")},
                   base_url=E.B, content_type="multipart/form-data")
    assert E.ANA[0] in r.text and f"#{oid}" in r.text
    assert E.eventos("FINGERPRINT_CREATED", "OK", f"orden={oid}") and E.eventos("FINGERPRINT_RECOVERED", "OK")
    # y el nombre del archivo NO es lo que identifica: renombrar no cambia nada
    assert fingerprint.extraer(COPIAS["png"], "png", clave)["user_id"] == uid
    anotar("09 Producto descargado -> fingerprint recuperable", f"Orden #{oid} de ana (usuario #{uid}):\n" + "\n".join(lineas) +
           "\n  La herramienta del ADMINISTRADOR identificó al comprador a partir de la copia 'filtrada' (PDF).")


def servicios_clave():
    return cripto.clave_simetrica(E.AJ.CLAVES_DIR, "fingerprint.key")


COPIAS = {}


# ---------------------------------------------------------------- 10. Descarga de producto no comprado
def test_10_cliente_descarga_producto_no_comprado_rechazado():
    n = E.Navegador.como(E.LUIS)
    oid = E.comprar(n, (2,))                                      # luis solo compró el producto 2
    ok = n.get(f"/descargas/{oid}/2").status_code
    r_otro_producto = n.get(f"/descargas/{oid}/3").status_code    # producto que NO está en su orden
    ana_orden = E.consulta("SELECT id FROM orders WHERE user_id = (SELECT id FROM users WHERE email = ?) AND status = 'PAGADA' LIMIT 1", (E.ANA[0],))[0][0]
    r_orden_ajena = n.get(f"/descargas/{ana_orden}/1").status_code  # orden de otra persona
    pendiente = E.Navegador.como(E.LUIS)
    pendiente.post("/carrito/agregar/4")
    o2 = int(pendiente.post("/ordenes").headers["Location"].rsplit("/", 1)[1])
    r_sin_pagar = pendiente.get(f"/descargas/{o2}/4").status_code   # orden creada pero NO pagada
    assert (ok, r_otro_producto, r_orden_ajena, r_sin_pagar) == (200, 403, 403, 403)
    assert E.eventos("DOWNLOAD", "DENEGADO")
    anotar("10 Descarga de producto no comprado", f"Producto comprado -> {ok}; producto fuera de su orden -> {r_otro_producto}; orden de otra persona -> {r_orden_ajena}; orden sin pagar -> {r_sin_pagar}. Intentos registrados como DOWNLOAD/DENEGADO.")


# ---------------------------------------------------------------- 11-12. Hash de archivos
def test_11_archivo_original_hash_esperado():
    with E.app().app_context():
        filas = E.consulta("SELECT * FROM products ORDER BY id")
        lineas = []
        for p in filas:
            datos = servicios.leer_producto(p)                    # descifra y compara con el SHA-256 de la BD
            assert cripto.sha256_bytes(datos) == p["file_hash"]
            lineas.append(f"  producto #{p['id']} {p['download_name']}: SHA-256 {p['file_hash'][:24]}… == calculado ✔")
    anotar("11 Archivo original -> hash esperado", "\n".join(lineas))


def test_12_archivo_modificado_hash_diferente():
    with E.app().app_context():
        p = E.consulta("SELECT * FROM products WHERE id = 2")[0]
        original = servicios.leer_producto(p)
        modificado = original.replace(b"TLS", b"tls", 1)           # cambio de un solo carácter
        assert modificado != original and cripto.sha256_bytes(modificado) != p["file_hash"]
        # alteración del archivo cifrado en disco: AES-GCM + SHA-256 lo detectan al leerlo
        ruta = E.AJ.PRODUCTOS_DIR / p["file_name"]
        bueno = ruta.read_bytes()
        ruta.write_bytes(bueno[:40] + bytes([bueno[40] ^ 1]) + bueno[41:])
        try:
            servicios.leer_producto(p)
            raise AssertionError("no se detectó la alteración")
        except servicios.ErrorIntegridad as e:
            detectado = str(e)
        finally:
            ruta.write_bytes(bueno)
    anotar("12 Archivo modificado -> hash diferente", f"Cambiar 1 carácter: SHA-256 original {p['file_hash'][:16]}… vs modificado {cripto.sha256_bytes(modificado)[:16]}…\n"
           f"  Alterar 1 bit del .enc en disco -> {detectado}")


# ---------------------------------------------------------------- 13. Respaldo y restauración
def test_13_restauracion_de_respaldo_recupera_informacion():
    n = E.Navegador.como(E.ANA)
    oid = E.comprar(n, (1,))
    antes = respaldo.resumen(E.AJ)
    zip_ = respaldo.crear_respaldo(E.AJ)
    # desastre: se pierde la BD y los productos
    E.AJ.DB_PATH.unlink()
    for f in E.AJ.PRODUCTOS_DIR.glob("*.enc"):
        f.unlink()
    assert not E.AJ.DB_PATH.exists() and not list(E.AJ.PRODUCTOS_DIR.glob("*.enc"))
    despues = respaldo.restaurar(zip_, E.AJ)
    assert despues == antes, (antes, despues)
    assert despues["integridad_bd"] == "ok" and despues["productos_verificados"] == despues["products"]
    # y la app sigue funcionando con lo restaurado: la orden y el comprobante están, y se puede volver a descargar
    n2 = E.Navegador.como(E.ANA)
    assert "FIRMA VÁLIDA" in n2.get(f"/comprobantes/{oid}").text and n2.get(f"/descargas/{oid}/1").status_code == 200
    anotar("13 Restauración de respaldo", f"Respaldo {zip_.name}. Se borraron BD y productos; tras restaurar: " +
           ", ".join(f"{k}={v}" for k, v in despues.items()) + ". La orden, el comprobante (firma válida) y la descarga funcionan.")
