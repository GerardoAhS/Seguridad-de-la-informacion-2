"""Funciones públicas (catálogo, registro, login, recuperación) y perfil."""
import hashlib
import hmac
import re
import secrets

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .seguridad import avisar as flash
from . import correo, eventos, seguridad, servicios
from .db import ahora, en_minutos, get_db

bp = Blueprint("publico", __name__)
MENSAJE_LOGIN = "Credenciales inválidas, o cuenta bloqueada/desactivada temporalmente."


def _like(texto):
    return "%" + texto.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@bp.route("/")
def catalogo():
    q = request.args.get("q", "").strip()[:80]
    cat = request.args.get("cat", "").strip()
    cat = cat if cat in servicios.CATEGORIAS else ""
    sql, params = ("SELECT id, name, description, price_cents, file_type, category, created_at FROM products "
                   "WHERE status = 'ACTIVO'"), []
    if cat:
        sql += " AND category = ?"
        params.append(cat)
    if q:
        sql += " AND (name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\')"
        params += [_like(q)] * 3
    productos = get_db().execute(sql + " ORDER BY id DESC", params).fetchall()
    conteo = {r["category"]: r["n"] for r in get_db().execute(
        "SELECT category, COUNT(*) n FROM products WHERE status = 'ACTIVO' GROUP BY category")}
    nuevos = {r["id"] for r in get_db().execute("SELECT id FROM products WHERE status = 'ACTIVO' ORDER BY id DESC LIMIT 4")}
    return render_template("catalogo.html", productos=productos, q=q, cat=cat, conteo=conteo,
                           total=sum(conteo.values()), nuevos=nuevos)


@bp.route("/producto/<int:pid>")
def producto(pid):
    p = get_db().execute("SELECT id, name, description, price_cents, file_type, category, highlights FROM products "
                         "WHERE id = ? AND status = 'ACTIVO'", (pid,)).fetchone()
    if p is None:
        abort(404)
    relacionados = get_db().execute("SELECT id, name, price_cents, file_type, category FROM products WHERE status = 'ACTIVO' "
                                    "AND category = ? AND id != ? ORDER BY id DESC LIMIT 3", (p["category"], pid)).fetchall()
    return render_template("producto.html", p=p, puntos=[l for l in p["highlights"].splitlines() if l.strip()],
                           relacionados=relacionados)


@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        nombre = request.form.get("name", "").strip()
        pw, pw2 = request.form.get("password", ""), request.form.get("password2", "")
        error = None
        if not seguridad.email_valido(email):
            error = "Correo electrónico no válido."
        elif not seguridad.nombre_valido(nombre):
            error = "Nombre no válido (2 a 80 caracteres, sin símbolos < >)."
        elif pw != pw2:
            error = "Las contraseñas no coinciden."
        else:
            error = seguridad.validar_password(pw, email)
        if error is None:
            existe = get_db().execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
            if existe:
                error = "No fue posible completar el registro con esos datos."   # no revela si el correo ya existe
                eventos.registrar("USER_REGISTERED", "RECHAZADO", "correo ya registrado", email=email)
        if error:
            flash(error, "error")
            return render_template("registro.html", email=email, nombre=nombre), 400
        cur = get_db().execute("INSERT INTO users(email, password_hash, name, role, status, created_at, email_verified) "
                               "VALUES(?,?,?,'CLIENTE','ACTIVO',?,0)",
                               (email, seguridad.hash_password(pw), nombre, ahora()))
        eventos.registrar("USER_REGISTERED", "OK", "rol=CLIENTE (pendiente de confirmar correo)", email=email, user_id=cur.lastrowid)
        u = get_db().execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        _enviar_verificacion(u)
        flash(f"Cuenta creada. Te enviamos un código de 6 dígitos a {email} para confirmar tu correo.", "ok")
        return redirect(url_for("publico.verificar_correo", email=email))
    return render_template("registro.html", email="", nombre="")


@bp.route("/login", methods=["GET", "POST"])
def login():
    siguiente = seguridad.destino_seguro(request.values.get("next"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        pw = request.form.get("password", "")[:200]
        if seguridad.cuenta_bloqueada(email):
            seguridad.verificar_falso(pw)
            eventos.registrar("LOGIN_FAILED", "BLOQUEADO", "demasiados intentos fallidos", email=email)
            flash(MENSAJE_LOGIN, "error")
            return render_template("login.html", siguiente=siguiente), 429
        u = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if u is None:
            seguridad.verificar_falso(pw)
            ok = False
        else:
            ok = seguridad.verificar_password(pw, u["password_hash"]) and u["status"] == "ACTIVO"
        if not ok:
            eventos.registrar("LOGIN_FAILED", "RECHAZADO",
                              "usuario inexistente" if u is None else ("cuenta desactivada" if u["status"] != "ACTIVO" else "contraseña incorrecta"),
                              email=email, user_id=u["id"] if u else None)
            flash(MENSAJE_LOGIN, "error")
            return render_template("login.html", siguiente=siguiente), 401
        if not u["email_verified"]:
            eventos.registrar("LOGIN_PENDING_VERIFICATION", "PENDIENTE", "correo sin confirmar", email=u["email"], user_id=u["id"])
            enviado = _enviar_verificacion(u, solo_si_puede=True)
            flash("Confirma tu correo antes de entrar." + (" Te enviamos un código nuevo." if enviado else
                  " Usa el código que te enviamos."), "error")
            return redirect(url_for("publico.verificar_correo", email=u["email"]))
        get_db().execute("UPDATE users SET last_login = ? WHERE id = ?", (ahora(), u["id"]))
        seguridad.iniciar_sesion_usuario(u["id"])
        eventos.registrar("LOGIN_SUCCESS", "OK", f"rol={u['role']}", email=u["email"], user_id=u["id"])
        return redirect(siguiente or url_for("publico.catalogo"))
    return render_template("login.html", siguiente=siguiente)


@bp.route("/logout", methods=["POST"])
def logout():
    if g.usuario is not None:
        eventos.registrar("LOGOUT", "OK")
    seguridad.cerrar_sesion_actual()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("publico.catalogo"))


# ---------------------------------------------------------------- códigos por correo
def _codigo():
    return f"{secrets.randbelow(10 ** 6):06d}"


def _hash_codigo(proposito, user_id, codigo):
    return hashlib.sha256(f"{proposito}:{user_id}:{codigo}".encode()).hexdigest()


def _enviar(funcion, u, *args):
    """Envía el correo; si el SMTP falla se registra el evento (sin el código) y se devuelve False."""
    try:
        via = funcion(u["email"], u["name"], *args)
        eventos.registrar("EMAIL_SENT", "OK", f"via={via}", email=u["email"], user_id=u["id"])
        return True
    except Exception as e:                                    # smtplib.SMTPException, OSError, ssl.SSLError...
        eventos.registrar("EMAIL_FAILED", "ERROR", f"{type(e).__name__}", email=u["email"], user_id=u["id"])
        return False


def _enviar_verificacion(u, solo_si_puede=False):
    """Genera un código de confirmación (invalida los anteriores) y lo envía. Respeta una espera mínima entre envíos."""
    aj = current_app.config["AJUSTES"]
    db = get_db()
    ultimo = db.execute("SELECT created_at FROM email_verifications WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                        (u["id"],)).fetchone()
    import datetime
    if ultimo and solo_si_puede:
        hace = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - \
            datetime.datetime.strptime(ultimo["created_at"], "%Y-%m-%d %H:%M:%S")
        if hace.total_seconds() < aj.REENVIO_SEGUNDOS:
            return False
    codigo = _codigo()
    db.execute("UPDATE email_verifications SET used = 1 WHERE user_id = ? AND used = 0", (u["id"],))
    db.execute("INSERT INTO email_verifications(user_id, code_hash, expires_at, created_at) VALUES(?,?,?,?)",
               (u["id"], _hash_codigo("VERIFICAR", u["id"], codigo), en_minutos(aj.VERIFICACION_MINUTOS), ahora()))
    db.commit()
    return _enviar(correo.enviar_codigo_verificacion, u, codigo, aj.VERIFICACION_MINUTOS)


def _comprobar_codigo(tabla, proposito, u, codigo):
    """Compara el código con el vigente del usuario. Cuenta intentos y lo invalida al llegar al límite."""
    aj = current_app.config["AJUSTES"]
    db = get_db()
    extra = " AND code_hash != ''" if tabla == "password_resets" else ""
    clave = "token_hash" if tabla == "password_resets" else "id"
    fila = db.execute(f"SELECT {clave} AS ref, code_hash, attempts FROM {tabla} WHERE user_id = ? AND used = 0 "
                      f"AND expires_at >= ?{extra} ORDER BY rowid DESC LIMIT 1", (u["id"], ahora())).fetchone()
    if fila is None:
        return None
    if hmac.compare_digest(fila["code_hash"], _hash_codigo(proposito, u["id"], codigo)):
        return fila["ref"]
    intentos = fila["attempts"] + 1
    db.execute(f"UPDATE {tabla} SET attempts = ?, used = ? WHERE {clave} = ?",
               (intentos, 1 if intentos >= aj.MAX_INTENTOS_CODIGO else 0, fila["ref"]))
    db.commit()
    return None


@bp.route("/verificar-correo", methods=["GET", "POST"])
def verificar_correo():
    email = request.values.get("email", "").strip().lower()[:254]
    if request.method == "POST":
        u = get_db().execute("SELECT * FROM users WHERE email = ? AND status = 'ACTIVO'", (email,)).fetchone()
        if request.form.get("accion") == "reenviar":
            if u and not u["email_verified"]:
                _enviar_verificacion(u, solo_si_puede=True)
            flash("Si la cuenta está pendiente de confirmar, enviamos un código nuevo (espera un minuto entre envíos).", "ok")
            return redirect(url_for("publico.verificar_correo", email=email))
        codigo = re.sub(r"\D", "", request.form.get("codigo", ""))[:6]
        ref = _comprobar_codigo("email_verifications", "VERIFICAR", u, codigo) if u and not u["email_verified"] and len(codigo) == 6 else None
        if ref is None:
            eventos.registrar("EMAIL_VERIFIED", "RECHAZADO", "código inválido, vencido o agotado", email=email)
            flash("El código no es válido o ya venció. Revisa tu correo o pide uno nuevo.", "error")
            return render_template("verificar_correo.html", email=email), 400
        get_db().execute("UPDATE email_verifications SET used = 1 WHERE id = ?", (ref,))
        get_db().execute("UPDATE users SET email_verified = 1 WHERE id = ?", (u["id"],))
        eventos.registrar("EMAIL_VERIFIED", "OK", email=u["email"], user_id=u["id"])
        flash("¡Correo confirmado! Ya puedes iniciar sesión.", "ok")
        return redirect(url_for("publico.login"))
    return render_template("verificar_correo.html", email=email)


# ---------------------------------------------------------------- recuperación de contraseña
@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    aj = current_app.config["AJUSTES"]
    demo = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:254]
        u = get_db().execute("SELECT * FROM users WHERE email = ? AND status = 'ACTIVO'", (email,)).fetchone()
        if u:
            token, codigo = secrets.token_urlsafe(32), _codigo()
            get_db().execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (u["id"],))
            get_db().execute("INSERT INTO password_resets(token_hash, user_id, expires_at, code_hash) VALUES(?,?,?,?)",
                             (hashlib.sha256(token.encode()).hexdigest(), u["id"], en_minutos(aj.RESET_MINUTOS),
                              _hash_codigo("RECUPERAR", u["id"], codigo)))
            get_db().commit()
            enlace = f"{request.host_url.rstrip('/')}{url_for('publico.restablecer', token=token)}"
            _enviar(correo.enviar_codigo_recuperacion, u, codigo, enlace, aj.RESET_MINUTOS)
            eventos.registrar("PASSWORD_RESET_REQUESTED", "OK", email=u["email"], user_id=u["id"])
            demo = {"codigo": codigo, "enlace": enlace} if aj.DEMO_MOSTRAR_ENLACE else None
        else:
            eventos.registrar("PASSWORD_RESET_REQUESTED", "IGNORADO", "correo no registrado o cuenta desactivada", email=email)
        flash("Si el correo está registrado, te enviamos un código (token) para restablecer la contraseña.", "ok")
        return render_template("restablecer_codigo.html", email=email, demo=demo)
    return render_template("recuperar.html", simulado=not correo.smtp_configurado())


def _guardar_nueva(u, pw, pw2, plantilla, **ctx):
    error = "Las contraseñas no coinciden." if pw != pw2 else seguridad.validar_password(pw, u["email"])
    if error:
        flash(error, "error")
        return render_template(plantilla, **ctx), 400
    get_db().execute("UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?",   # recibir el código prueba el correo
                     (seguridad.hash_password(pw), u["id"]))
    seguridad.revocar_sesiones_de(u["id"])                  # cualquier sesión abierta deja de valer
    eventos.registrar("PASSWORD_RESET", "OK", email=u["email"], user_id=u["id"])
    flash("Contraseña actualizada. Inicia sesión con la nueva.", "ok")
    return redirect(url_for("publico.login"))


@bp.route("/restablecer", methods=["GET", "POST"])
def restablecer_codigo():
    """Restablecer con el CÓDIGO (token de 6 dígitos) que llegó por correo."""
    email = request.values.get("email", "").strip().lower()[:254]
    if request.method == "POST":
        u = get_db().execute("SELECT * FROM users WHERE email = ? AND status = 'ACTIVO'", (email,)).fetchone()
        codigo = re.sub(r"\D", "", request.form.get("codigo", ""))[:6]
        ref = _comprobar_codigo("password_resets", "RECUPERAR", u, codigo) if u and len(codigo) == 6 else None
        if ref is None:
            eventos.registrar("PASSWORD_RESET", "RECHAZADO", "código inválido, usado, vencido o agotado", email=email)
            flash("El código no es válido o ya venció. Solicita uno nuevo si es necesario.", "error")
            return render_template("restablecer_codigo.html", email=email, demo=None), 400
        resp = _guardar_nueva(u, request.form.get("password", ""), request.form.get("password2", ""),
                              "restablecer_codigo.html", email=email, demo=None)
        if not isinstance(resp, tuple):                      # éxito: el código queda usado
            get_db().execute("UPDATE password_resets SET used = 1 WHERE token_hash = ?", (ref,))
            get_db().commit()
        return resp
    return render_template("restablecer_codigo.html", email=email, demo=None)


def _token_vigente(token):
    return get_db().execute("SELECT * FROM password_resets WHERE token_hash = ? AND used = 0 AND expires_at >= ?",
                            (hashlib.sha256(token.encode()).hexdigest(), ahora())).fetchone()


@bp.route("/restablecer/<token>", methods=["GET", "POST"])
def restablecer(token):
    """Restablecer con el ENLACE del mismo correo."""
    r = _token_vigente(token)
    if r is None:
        eventos.registrar("PASSWORD_RESET", "RECHAZADO", "token inválido, usado o vencido")
        flash("El enlace no es válido o ya venció. Solicita uno nuevo.", "error")
        return redirect(url_for("publico.recuperar"))
    if request.method == "POST":
        u = get_db().execute("SELECT * FROM users WHERE id = ?", (r["user_id"],)).fetchone()
        resp = _guardar_nueva(u, request.form.get("password", ""), request.form.get("password2", ""),
                              "restablecer.html", token=token)
        if not isinstance(resp, tuple):
            get_db().execute("UPDATE password_resets SET used = 1 WHERE token_hash = ?", (r["token_hash"],))
            get_db().commit()
        return resp
    return render_template("restablecer.html", token=token)


# ---------------------------------------------------------------- perfil
@bp.route("/perfil", methods=["GET", "POST"])
@seguridad.requiere("perfil:editar")
def perfil():
    if request.method == "POST":
        nombre = request.form.get("name", "").strip()
        actual, nueva = request.form.get("password_actual", ""), request.form.get("password_nueva", "")
        if not seguridad.nombre_valido(nombre):
            flash("Nombre no válido.", "error")
            return render_template("perfil.html"), 400
        if nueva:
            if not seguridad.verificar_password(actual, g.usuario["password_hash"]):
                eventos.registrar("PASSWORD_CHANGED", "RECHAZADO", "contraseña actual incorrecta")
                flash("La contraseña actual no es correcta.", "error")
                return render_template("perfil.html"), 400
            error = seguridad.validar_password(nueva, g.usuario["email"])
            if error:
                flash(error, "error")
                return render_template("perfil.html"), 400
            get_db().execute("UPDATE users SET password_hash = ? WHERE id = ?", (seguridad.hash_password(nueva), g.usuario["id"]))
            eventos.registrar("PASSWORD_CHANGED", "OK")
        get_db().execute("UPDATE users SET name = ? WHERE id = ?", (nombre, g.usuario["id"]))
        eventos.registrar("PROFILE_UPDATED", "OK")
        flash("Perfil actualizado.", "ok")
        return redirect(url_for("publico.perfil"))
    return render_template("perfil.html")
