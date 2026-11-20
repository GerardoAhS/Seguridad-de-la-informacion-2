"""Contraseñas, sesiones, CSRF, control de acceso por roles y validación de entradas."""
import base64
import hashlib
import hmac
import os
import re
import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import abort, current_app, g, redirect, request, url_for

from . import eventos
from .db import ahora, en_minutos, get_db, get_setting

# ================================================================ contraseñas
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError
    _PH = PasswordHasher()          # Argon2id con parámetros por defecto de la biblioteca (sal incluida)
except ImportError:                 # entorno sin argon2-cffi: scrypt (KDF de memoria dura, de hashlib)
    _PH = None

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1


def _scrypt(password, sal, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P):
    return hashlib.scrypt(password.encode(), salt=sal, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)


def algoritmo_password():
    return "argon2id" if _PH else "scrypt"


def hash_password(password: str) -> str:
    if _PH:
        return _PH.hash(password)
    sal = os.urandom(16)
    b = base64.b64encode
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b(sal).decode()}${b(_scrypt(password, sal)).decode()}"


def verificar_password(password: str, almacenado: str) -> bool:
    try:
        if almacenado.startswith("$argon2"):
            return bool(_PH) and _PH.verify(almacenado, password)
        if almacenado.startswith("scrypt$"):
            _, n, r, p, sal, h = almacenado.split("$")
            calc = _scrypt(password, base64.b64decode(sal), int(n), int(r), int(p))
            return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False
    return False


_HASH_FALSO = None


def verificar_falso(password):
    """Gasta el mismo tiempo cuando el usuario no existe (evita enumerar cuentas midiendo la respuesta)."""
    global _HASH_FALSO
    if _HASH_FALSO is None:
        _HASH_FALSO = hash_password("contraseña-que-nadie-usa")
    verificar_password(password, _HASH_FALSO)


_COMUNES = {"password123", "contraseña123", "1234567890", "qwertyuiop", "administrador", "password1234"}


def validar_password(password: str, email: str = ""):
    """Devuelve un mensaje de error o None si la contraseña cumple la política."""
    if len(password) < 10:
        return "La contraseña debe tener al menos 10 caracteres."
    if len(password) > 128:
        return "La contraseña es demasiado larga (máximo 128)."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "La contraseña debe combinar letras y números."
    if password.lower() in _COMUNES or (email and password.lower() == email.lower()):
        return "Esa contraseña es demasiado común o predecible."
    return None


# ================================================================ validación de entradas
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$")


def email_valido(email: str) -> bool:
    return bool(_EMAIL.match(email)) and len(email) <= 254


def nombre_valido(nombre: str) -> bool:
    return 2 <= len(nombre) <= 80 and not re.search(r"[<>\x00-\x1f]", nombre)


def destino_seguro(destino):
    """Anti open-redirect: solo rutas relativas de este mismo sitio."""
    if destino and destino.startswith("/") and not destino.startswith("//") and "\\" not in destino:
        if not urlparse(destino).netloc:
            return destino
    return None


# ================================================================ roles y privilegio mínimo
PERMISOS = {
    "CLIENTE": {"perfil:editar", "catalogo:ver", "carrito:usar", "orden:crear", "orden:pagar", "orden:ver_propias",
                "producto:descargar_propios", "comprobante:ver_propios", "comprobante:verificar"},
    "OPERADOR": {"catalogo:ver", "producto:registrar", "producto:modificar", "producto:activar", "precio:modificar",
                 "orden:ver_todas", "orden:actualizar_estado", "perfil:editar"},
    "ADMINISTRADOR": {"catalogo:ver", "usuario:consultar", "usuario:activar", "rol:asignar", "sesion:revocar",
                      "evento:consultar", "config:administrar", "fingerprint:recuperar", "perfil:editar"},
}


def tiene_permiso(rol, permiso):
    return permiso in PERMISOS.get(rol, set())


def login_requerido(f):
    @wraps(f)
    def interior(*a, **k):
        if g.usuario is None:
            return redirect(url_for("publico.login", next=request.full_path.rstrip("?")))
        return f(*a, **k)
    return interior


def requiere(permiso):
    """Autorización por permiso. Deniega por defecto y registra el intento (ACCESS_DENIED)."""
    def deco(f):
        @wraps(f)
        def interior(*a, **k):
            if g.usuario is None:
                return redirect(url_for("publico.login", next=request.full_path.rstrip("?")))
            if not tiene_permiso(g.usuario["role"], permiso):
                eventos.registrar("ACCESS_DENIED", "DENEGADO", f"permiso={permiso} ruta={request.path}")
                abort(403)
            return f(*a, **k)
        return interior
    return deco


# ================================================================ sesiones del lado del servidor
COOKIE = "sid"


def _hash_sesion_destino():
    return _h(g.cookie_nueva) if g.get("cookie_nueva") else g.sesion["id_hash"]


def avisar(mensaje, categoria="ok"):
    """Mensaje para la siguiente pantalla. Se guarda en la sesión DEL SERVIDOR (no se usa la cookie firmada de Flask)."""
    import json
    con = get_db()
    fila = con.execute("SELECT flash FROM sessions WHERE id_hash = ?", (_hash_sesion_destino(),)).fetchone()
    if fila is not None:
        lista = json.loads(fila["flash"]) + [[categoria, mensaje]]
        con.execute("UPDATE sessions SET flash = ? WHERE id_hash = ?", (json.dumps(lista), _hash_sesion_destino()))
        con.commit()


def avisos():
    """Devuelve y limpia los avisos pendientes."""
    import json
    con = get_db()
    destino = _hash_sesion_destino()
    fila = con.execute("SELECT flash FROM sessions WHERE id_hash = ?", (destino,)).fetchone()
    lista = json.loads(fila["flash"]) if fila else []
    if lista:
        con.execute("UPDATE sessions SET flash = '[]' WHERE id_hash = ?", (destino,))
        con.commit()
    return lista


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def crear_sesion(user_id=None):
    """Devuelve el token (se entrega por cookie). En la BD solo queda su hash."""
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    minutos = get_setting("session_minutes", current_app.config["AJUSTES"].SESION_MINUTOS)
    con = get_db()
    con.execute("DELETE FROM sessions WHERE expires_at < ?", (ahora(),))
    con.execute("INSERT INTO sessions(id_hash, user_id, csrf_token, created_at, expires_at, ip) VALUES(?,?,?,?,?,?)",
                (_h(token), user_id, csrf, ahora(), en_minutos(minutos), request.remote_addr))
    con.commit()
    return token


def cargar_sesion():
    """before_request: valida cookie, expiración, revocación y estado de la cuenta."""
    aj = current_app.config["AJUSTES"]
    g.usuario, g.sesion, g.cookie_nueva = None, None, None
    token = request.cookies.get(COOKIE)
    fila = None
    if token:
        fila = get_db().execute("SELECT * FROM sessions WHERE id_hash = ?", (_h(token),)).fetchone()
        if fila and (fila["revoked"] or fila["expires_at"] < ahora()):
            fila = None
    if fila is None:
        g.cookie_nueva = crear_sesion(None)
        fila = get_db().execute("SELECT * FROM sessions WHERE id_hash = ?", (_h(g.cookie_nueva),)).fetchone()
    else:
        # límite absoluto + ventana deslizante por inactividad
        import datetime
        creada = datetime.datetime.strptime(fila["created_at"], "%Y-%m-%d %H:%M:%S")
        limite = creada + datetime.timedelta(hours=aj.SESION_MAX_HORAS)
        nuevo = min(en_minutos(get_setting("session_minutes", aj.SESION_MINUTOS)), limite.strftime("%Y-%m-%d %H:%M:%S"))
        get_db().execute("UPDATE sessions SET expires_at = ? WHERE id_hash = ?", (nuevo, fila["id_hash"]))
        get_db().commit()
    g.sesion = fila
    if fila["user_id"]:
        u = get_db().execute("SELECT * FROM users WHERE id = ?", (fila["user_id"],)).fetchone()
        if u and u["status"] == "ACTIVO":
            g.usuario = u


def iniciar_sesion_usuario(user_id):
    """Rota la sesión al autenticar (anti session fixation): la anónima se destruye y se crea una nueva."""
    if g.sesion is not None:
        get_db().execute("DELETE FROM sessions WHERE id_hash = ?", (g.sesion["id_hash"],))
    g.cookie_nueva = crear_sesion(user_id)


def cerrar_sesion_actual():
    if g.sesion is not None:
        get_db().execute("DELETE FROM sessions WHERE id_hash = ?", (g.sesion["id_hash"],))
        get_db().commit()
    g.cookie_nueva = crear_sesion(None)


def revocar_sesiones_de(user_id):
    get_db().execute("UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,))


def poner_cookie(respuesta):
    if g.get("cookie_nueva"):
        aj = current_app.config["AJUSTES"]
        respuesta.set_cookie(COOKIE, g.cookie_nueva, httponly=True, secure=aj.COOKIE_SECURE, samesite="Lax",
                             max_age=aj.SESION_MAX_HORAS * 3600, path="/")
    return respuesta


# ================================================================ CSRF
def verificar_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        enviado = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not hmac.compare_digest(enviado, g.sesion["csrf_token"]):
            eventos.registrar("CSRF_REJECTED", "DENEGADO", f"ruta={request.path}")
            abort(400)


# ================================================================ bloqueo por intentos fallidos
def cuenta_bloqueada(email):
    aj = current_app.config["AJUSTES"]
    import datetime
    desde = (datetime.datetime.now(datetime.timezone.utc)
             - datetime.timedelta(minutes=aj.VENTANA_BLOQUEO_MIN)).strftime("%Y-%m-%d %H:%M:%S")
    n = get_db().execute(
        "SELECT COUNT(*) c FROM security_events WHERE user_email = ? AND event = 'LOGIN_FAILED' AND created_at >= ? "
        "AND created_at > COALESCE((SELECT MAX(created_at) FROM security_events WHERE user_email = ? AND event = 'LOGIN_SUCCESS'), '')",
        (email, desde, email)).fetchone()["c"]
    return n >= get_setting("max_login_attempts", aj.MAX_INTENTOS)
