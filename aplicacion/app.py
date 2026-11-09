import os
import re
import sqlite3

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUTA_BD = os.path.join(RAIZ, "base_de_datos", "tienda.db")

app = Flask(__name__)
# En producción la llave debe venir de una variable de entorno
app.secret_key = os.environ.get("SECRET_KEY", "clave-solo-para-desarrollo")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ph = PasswordHasher()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- Base de datos ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(RUTA_BD)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def registrar_evento(email, evento, resultado):
    """Guarda un evento de seguridad (login, logout, etc.)."""
    db = get_db()
    db.execute(
        "INSERT INTO security_events (user_email, event, result, origin) VALUES (?, ?, ?, ?)",
        (email, evento, resultado, request.remote_addr),
    )
    db.commit()


# ---------- Usuario actual ----------
@app.before_request
def cargar_usuario():
    g.usuario = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.usuario = get_db().execute(
            "SELECT id, email, name, role FROM users WHERE id = ? AND status = 'ACTIVO'",
            (user_id,),
        ).fetchone()
        if g.usuario is None:
            session.clear()


# ---------- Rutas públicas ----------
@app.route("/")
def catalogo():
    productos = get_db().execute(
        "SELECT id, name, description, price FROM products WHERE status = 'ACTIVO'"
    ).fetchall()
    return render_template("catalogo.html", productos=productos)


@app.route("/producto/<int:producto_id>")
def producto(producto_id):
    p = get_db().execute(
        "SELECT id, name, description, price FROM products WHERE id = ? AND status = 'ACTIVO'",
        (producto_id,),
    ).fetchone()
    if p is None:
        abort(404)
    return render_template("producto.html", p=p)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        clave = request.form.get("clave", "")

        if not nombre or len(nombre) > 80:
            flash("Escribe tu nombre (máximo 80 caracteres).")
        elif not EMAIL_RE.match(email) or len(email) > 120:
            flash("El correo no es válido.")
        elif len(clave) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.")
        else:
            db = get_db()
            existe = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existe:
                flash("Ese correo ya está registrado.")
            else:
                # Todo registro nuevo entra como CLIENTE
                db.execute(
                    "INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, 'CLIENTE')",
                    (email, ph.hash(clave), nombre),
                )
                db.commit()
                flash("Cuenta creada. Ya puedes iniciar sesión.")
                return redirect(url_for("login"))
    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        clave = request.form.get("clave", "")
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        valido = False
        if u is not None and u["status"] == "ACTIVO":
            try:
                valido = ph.verify(u["password_hash"], clave)
            except VerifyMismatchError:
                valido = False

        if valido:
            session.clear()
            session["user_id"] = u["id"]
            db.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (u["id"],))
            db.commit()
            registrar_evento(email, "LOGIN_SUCCESS", "OK")
            return redirect(url_for("catalogo"))

        registrar_evento(email, "LOGIN_FAILED", "FALLO")
        # Mismo mensaje exista o no el correo, para no dar pistas
        flash("Correo o contraseña incorrectos.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if g.usuario:
        registrar_evento(g.usuario["email"], "LOGOUT", "OK")
    session.clear()
    return redirect(url_for("catalogo"))


@app.errorhandler(404)
def no_encontrado(e):
    return render_template("error.html", mensaje="Página no encontrada."), 404


@app.errorhandler(500)
def error_interno(e):
    return render_template("error.html", mensaje="Ocurrió un error en el servidor."), 500


if __name__ == "__main__":
    app.run(debug=False, port=5000)
