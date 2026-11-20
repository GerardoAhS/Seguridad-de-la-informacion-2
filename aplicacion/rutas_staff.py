"""Funciones del OPERADOR (catálogo y pedidos) y del ADMINISTRADOR (usuarios, sesiones, eventos, configuración)."""
import secrets

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .seguridad import avisar as flash
from . import correo, cripto, eventos, fingerprint, seguridad, servicios
from .db import get_db, get_setting, set_setting

bp = Blueprint("staff", __name__)

TRANSICIONES = {"PENDIENTE": {"CANCELADA"}, "PAGADA": {"COMPLETADA"}, "COMPLETADA": set(), "CANCELADA": set()}


# ================================================================ OPERADOR: catálogo
@bp.route("/operador/productos")
@seguridad.requiere("producto:modificar")
def op_productos():
    filas = get_db().execute("SELECT id, name, price_cents, file_type, file_hash, status, category FROM products ORDER BY id").fetchall()
    return render_template("op_productos.html", productos=filas)


def _leer_formulario_producto(actual=None):
    nombre = request.form.get("name", "").strip()
    desc = request.form.get("description", "").strip()
    precio = servicios.parsear_precio(request.form.get("price", ""))
    if not (2 <= len(nombre) <= 120):
        return None, "El nombre debe tener entre 2 y 120 caracteres."
    if not (1 <= len(desc) <= 2000):
        return None, "La descripción es obligatoria (máximo 2000 caracteres)."
    if precio is None:
        return None, "Precio no válido (use formato 149.90, entre 0 y 100000)."
    categoria = request.form.get("category", actual["category"] if actual else "")       # al editar, si no viene, se conserva
    if categoria not in servicios.CATEGORIAS:
        return None, "Elige una categoría válida."
    texto = request.form.get("highlights", actual["highlights"] if actual else "")
    puntos = "\n".join(l.strip()[:150] for l in texto.splitlines() if l.strip())[:2000]
    return (nombre, desc, precio, categoria, puntos), None


@bp.route("/operador/productos/nuevo", methods=["GET", "POST"])
@seguridad.requiere("producto:registrar")
def op_producto_nuevo():
    if request.method == "POST":
        datos, error = _leer_formulario_producto()
        archivo = request.files.get("archivo")
        if error is None and (archivo is None or not archivo.filename):
            error = "Debes adjuntar el archivo del producto."
        if error is None:
            try:
                tipo = fingerprint.tipo_de(archivo.filename)
            except fingerprint.TipoNoSoportado:
                error = "Tipo de archivo no permitido (solo .txt, .md, .pdf, .png)."
        if error is None:
            contenido = archivo.read()
            if not contenido or not servicios.contenido_coherente(tipo, contenido):
                error = "El contenido del archivo no corresponde con su extensión."
        if error:
            flash(error, "error")
            return render_template("op_producto_form.html", p=None, categorias=servicios.CATEGORIAS), 400
        nombre, desc, precio, categoria, puntos = datos
        interno = secrets.token_hex(16) + ".enc"
        sha = servicios.guardar_producto_cifrado(contenido, interno)       # se cifra antes de tocar el disco de productos
        cur = get_db().execute(
            "INSERT INTO products(name, description, price_cents, file_name, download_name, file_type, file_hash, status, created_at, "
            "category, highlights) VALUES(?,?,?,?,?,?,?,'ACTIVO',datetime('now'),?,?)",
            (nombre, desc, precio, interno, servicios.nombre_descarga_seguro(archivo.filename), tipo, sha, categoria, puntos))
        eventos.registrar("PRODUCT_CREATED", "OK", f"producto={cur.lastrowid} sha256={sha[:16]}")
        flash("Producto registrado.", "ok")
        return redirect(url_for("staff.op_productos"))
    return render_template("op_producto_form.html", p=None, categorias=servicios.CATEGORIAS)


@bp.route("/operador/productos/<int:pid>", methods=["GET", "POST"])
@seguridad.requiere("producto:modificar")
def op_producto_editar(pid):
    p = get_db().execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        abort(404)
    if request.method == "POST":
        datos, error = _leer_formulario_producto(p)
        if error:
            flash(error, "error")
            return render_template("op_producto_form.html", p=p, categorias=servicios.CATEGORIAS), 400
        nombre, desc, precio, categoria, puntos = datos
        get_db().execute("UPDATE products SET name = ?, description = ?, price_cents = ?, category = ?, highlights = ? WHERE id = ?",
                         (nombre, desc, precio, categoria, puntos, pid))
        detalle = f"producto={pid}" + (f" precio {p['price_cents']}->{precio}" if precio != p["price_cents"] else "")
        eventos.registrar("PRODUCT_UPDATED", "OK", detalle)
        flash("Producto actualizado.", "ok")
        return redirect(url_for("staff.op_productos"))
    return render_template("op_producto_form.html", p=p, categorias=servicios.CATEGORIAS)


@bp.route("/operador/productos/<int:pid>/estado", methods=["POST"])
@seguridad.requiere("producto:activar")
def op_producto_estado(pid):
    p = get_db().execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        abort(404)
    nuevo = "INACTIVO" if p["status"] == "ACTIVO" else "ACTIVO"
    get_db().execute("UPDATE products SET status = ? WHERE id = ?", (nuevo, pid))
    eventos.registrar("PRODUCT_UPDATED", "OK", f"producto={pid} estado={nuevo}")
    return redirect(url_for("staff.op_productos"))


# ================================================================ OPERADOR: pedidos
@bp.route("/operador/ordenes")
@seguridad.requiere("orden:ver_todas")
def op_ordenes():
    filas = get_db().execute("SELECT o.id, o.total_cents, o.status, o.created_at, u.name FROM orders o "
                             "JOIN users u ON u.id = o.user_id ORDER BY o.id DESC").fetchall()
    return render_template("op_ordenes.html", ordenes=filas)


@bp.route("/operador/ordenes/<int:oid>", methods=["GET", "POST"])
@seguridad.requiere("orden:ver_todas")
def op_orden(oid):
    o = get_db().execute("SELECT o.*, u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?", (oid,)).fetchone()
    if o is None:
        abort(404)
    if request.method == "POST":
        if not seguridad.tiene_permiso(g.usuario["role"], "orden:actualizar_estado"):
            abort(403)
        nuevo = request.form.get("estado", "")
        if nuevo not in TRANSICIONES[o["status"]]:
            flash("Transición de estado no permitida.", "error")
            return redirect(url_for("staff.op_orden", oid=oid))
        get_db().execute("UPDATE orders SET status = ? WHERE id = ?", (nuevo, oid))
        eventos.registrar("ORDER_STATUS_CHANGED", "OK", f"orden={oid} {o['status']}->{nuevo}")
        return redirect(url_for("staff.op_orden", oid=oid))
    items = get_db().execute("SELECT p.name, i.price_cents FROM order_items i JOIN products p ON p.id = i.product_id "
                             "WHERE i.order_id = ?", (oid,)).fetchall()
    return render_template("op_orden.html", o=o, items=items, permitidos=sorted(TRANSICIONES[o["status"]]))


# ================================================================ ADMINISTRADOR: usuarios
@bp.route("/admin/usuarios")
@seguridad.requiere("usuario:consultar")
def admin_usuarios():
    filas = get_db().execute("SELECT id, email, name, role, status, created_at, last_login, email_verified FROM users ORDER BY id").fetchall()
    return render_template("admin_usuarios.html", usuarios=filas)


def _usuario_objetivo(uid):
    u = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if u is None:
        abort(404)
    return u


def _admins_activos():
    return get_db().execute("SELECT COUNT(*) c FROM users WHERE role = 'ADMINISTRADOR' AND status = 'ACTIVO'").fetchone()["c"]


@bp.route("/admin/usuarios/<int:uid>/rol", methods=["POST"])
@seguridad.requiere("rol:asignar")
def admin_rol(uid):
    u = _usuario_objetivo(uid)
    nuevo = request.form.get("rol", "")
    if nuevo not in seguridad.PERMISOS:
        flash("Rol no válido.", "error")
    elif u["id"] == g.usuario["id"]:
        flash("No puedes cambiar tu propio rol (separación de responsabilidades).", "error")
    elif u["role"] == "ADMINISTRADOR" and nuevo != "ADMINISTRADOR" and _admins_activos() <= 1:
        flash("Debe existir al menos un administrador activo.", "error")
    else:
        get_db().execute("UPDATE users SET role = ? WHERE id = ?", (nuevo, uid))
        seguridad.revocar_sesiones_de(uid)           # al cambiar privilegios, la sesión anterior deja de valer
        eventos.registrar("ROLE_CHANGED", "OK", f"usuario={uid} {u['role']}->{nuevo}")
        flash("Rol actualizado.", "ok")
    return redirect(url_for("staff.admin_usuarios"))


@bp.route("/admin/usuarios/<int:uid>/estado", methods=["POST"])
@seguridad.requiere("usuario:activar")
def admin_estado(uid):
    u = _usuario_objetivo(uid)
    if u["id"] == g.usuario["id"]:
        flash("No puedes desactivar tu propia cuenta.", "error")
    elif u["status"] == "ACTIVO":
        if u["role"] == "ADMINISTRADOR" and _admins_activos() <= 1:
            flash("Debe existir al menos un administrador activo.", "error")
        else:
            get_db().execute("UPDATE users SET status = 'DESACTIVADO' WHERE id = ?", (uid,))
            seguridad.revocar_sesiones_de(uid)
            eventos.registrar("ACCOUNT_DISABLED", "OK", f"usuario={uid}")
            flash("Cuenta desactivada y sesiones revocadas.", "ok")
    else:
        get_db().execute("UPDATE users SET status = 'ACTIVO' WHERE id = ?", (uid,))
        eventos.registrar("ACCOUNT_ENABLED", "OK", f"usuario={uid}")
        flash("Cuenta activada.", "ok")
    return redirect(url_for("staff.admin_usuarios"))


# ================================================================ ADMINISTRADOR: sesiones, eventos, configuración
@bp.route("/admin/sesiones")
@seguridad.requiere("sesion:revocar")
def admin_sesiones():
    filas = get_db().execute("SELECT s.id_hash, s.created_at, s.expires_at, s.ip, u.email FROM sessions s "
                             "JOIN users u ON u.id = s.user_id WHERE s.revoked = 0 AND s.expires_at >= datetime('now') "
                             "ORDER BY s.created_at DESC").fetchall()
    return render_template("admin_sesiones.html", sesiones=filas)


@bp.route("/admin/sesiones/revocar", methods=["POST"])
@seguridad.requiere("sesion:revocar")
def admin_revocar():
    ref = request.form.get("id_hash", "")
    fila = get_db().execute("SELECT s.id_hash, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?", (ref,)).fetchone()
    if fila is None:
        abort(404)
    get_db().execute("UPDATE sessions SET revoked = 1 WHERE id_hash = ?", (ref,))
    eventos.registrar("SESSION_REVOKED", "OK", f"sesion de {fila['email']}")
    flash("Sesión revocada.", "ok")
    return redirect(url_for("staff.admin_sesiones"))


@bp.route("/admin/eventos")
@seguridad.requiere("evento:consultar")
def admin_eventos():
    tipo = request.args.get("evento", "").strip()[:40]
    if tipo:
        filas = get_db().execute("SELECT * FROM security_events WHERE event = ? ORDER BY id DESC LIMIT 300", (tipo,)).fetchall()
    else:
        filas = get_db().execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 300").fetchall()
    tipos = [r["event"] for r in get_db().execute("SELECT DISTINCT event FROM security_events ORDER BY event")]
    return render_template("admin_eventos.html", eventos=filas, tipos=tipos, tipo=tipo)


@bp.route("/admin/configuracion", methods=["GET", "POST"])
@seguridad.requiere("config:administrar")
def admin_config():
    aj = current_app.config["AJUSTES"]
    if request.method == "POST":
        try:
            minutos = int(request.form.get("session_minutes", ""))
            intentos = int(request.form.get("max_login_attempts", ""))
            if not (5 <= minutos <= 240 and 3 <= intentos <= 20):
                raise ValueError
        except ValueError:
            flash("Valores fuera de rango (sesión 5-240 min, intentos 3-20).", "error")
            return redirect(url_for("staff.admin_config"))
        set_setting("session_minutes", minutos)
        set_setting("max_login_attempts", intentos)
        eventos.registrar("SETTINGS_CHANGED", "OK", f"session_minutes={minutos} max_login_attempts={intentos}")
        flash("Configuración guardada.", "ok")
        return redirect(url_for("staff.admin_config"))
    return render_template("admin_config.html", minutos=get_setting("session_minutes", aj.SESION_MINUTOS),
                           intentos=get_setting("max_login_attempts", aj.MAX_INTENTOS),
                           algoritmo=seguridad.algoritmo_password(), key_id=cripto.id_clave_publica(servicios.publica()),
                           smtp=(lambda c: f"{c.get('SMTP_USUARIO')} vía {c.get('SMTP_HOST')}" if correo.smtp_configurado() else None)(correo.configuracion()))


# ================================================================ ADMINISTRADOR: rastrear una copia sospechosa
def _ficha(user_id, order_id, product_id=None):
    db = get_db()
    u = db.execute("SELECT id, email, name FROM users WHERE id = ?", (user_id,)).fetchone()
    o = db.execute("SELECT id, status, total_cents, created_at FROM orders WHERE id = ?", (order_id,)).fetchone()
    p = db.execute("SELECT id, name FROM products WHERE id = ?", (product_id,)).fetchone() if product_id else None
    sql = ("SELECT d.created_at, d.ip, p.name FROM downloads d JOIN products p ON p.id = d.product_id "
           "WHERE d.user_id = ? AND d.order_id = ?" + (" AND d.product_id = ?" if product_id else "") + " ORDER BY d.id")
    desc = db.execute(sql, (user_id, order_id) + ((product_id,) if product_id else ())).fetchall()
    return {"user_id": user_id, "order_id": order_id, "product_id": product_id, "usuario": u, "orden": o,
            "producto": p, "descargas": desc}


@bp.route("/admin/fingerprint", methods=["GET", "POST"])
@seguridad.requiere("fingerprint:recuperar")
def admin_fingerprint():
    """Identifica al comprador a partir de una copia filtrada (huella invisible) o de un comprobante .json."""
    res = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        datos = archivo.read() if archivo and archivo.filename else b""
        res = {"metodo": None, "ficha": None, "nota": "", "tipo": None}
        if not datos:
            res["nota"] = "El archivo está vacío."
        elif datos.lstrip(b"\xef\xbb\xbf \r\n\t").startswith(b"{"):
            # Es un comprobante: se identifica la orden por su contenido firmado
            res["tipo"] = "json"
            doc, error = servicios.leer_documento(datos)
            analisis = servicios.analizar_documento(doc) if doc else {"valido": False, "motivo": error, "datos": None}
            c = analisis.get("datos") or {}
            if analisis["valido"]:
                res["metodo"] = "comprobante firmado"
                res["ficha"] = _ficha(c["usuario"]["id"], c["numero_orden"])
            res["nota"] = analisis["motivo"] + ("" if analisis["valido"] else
                          " Para rastrear a quien filtró un producto sube el archivo del PRODUCTO descargado (.pdf, .png, .md, .txt).")
        else:
            a = fingerprint.analizar(datos, servicios.clave_fingerprint())
            res["tipo"] = a["tipo"]
            h = a["huella"]
            if h:
                res["metodo"] = "huella invisible (HMAC verificado)"
                res["ficha"] = _ficha(h["user_id"], h["order_id"], h["product_id"])
            else:
                sha = cripto.sha256_bytes(datos)
                d = get_db().execute("SELECT user_id, order_id, product_id FROM downloads WHERE delivered_sha256 = ? "
                                     "ORDER BY id LIMIT 1", (sha,)).fetchone()
                original = get_db().execute("SELECT id, name FROM products WHERE file_hash = ?", (sha,)).fetchone()
                if d:
                    res["metodo"] = "SHA-256 idéntico a una copia entregada"
                    res["ficha"] = _ficha(d["user_id"], d["order_id"], d["product_id"])
                elif original:
                    res["nota"] = (f"Es el archivo ORIGINAL del producto «{original['name']}» (sin huella): "
                                   "no es una copia descargada por un cliente.")
                elif a["cargas_invalidas"]:
                    res["nota"] = ("El archivo SÍ contiene una marca con el formato de la plataforma, pero su HMAC no es válido: "
                                   "fue alterada o se generó con otra clave (¿se regeneró claves_privadas/fingerprint.key "
                                   "o se descargó desde otra instalación?).")
                else:
                    res["nota"] = ("No se encontró una huella en el archivo. Causas posibles: no es una copia descargada "
                                   "de la tienda, se convirtió a otro formato (p. ej. JPG, captura de pantalla, impresión), "
                                   "o el texto se copió a otro documento y se perdieron los caracteres invisibles.")
        if res["ficha"]:
            f = res["ficha"]
            eventos.registrar("FINGERPRINT_RECOVERED", "OK", f"usuario={f['user_id']} orden={f['order_id']} "
                              f"producto={f['product_id'] or '-'} metodo={res['metodo']}")
        else:
            eventos.registrar("FINGERPRINT_RECOVERED", "SIN_HUELLA", res["nota"][:150])
    return render_template("admin_fingerprint.html", res=res)
