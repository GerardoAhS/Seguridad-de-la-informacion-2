"""Plataforma segura de venta y distribución de contenido digital."""
import os
from pathlib import Path

from flask import Flask, g, render_template, request

from .ajustes import Ajustes


def create_app(ajustes: Ajustes | None = None):
    aj = ajustes or Ajustes()
    app = Flask(__name__)
    app.config["AJUSTES"] = aj
    app.config["MAX_CONTENT_LENGTH"] = aj.MAX_SUBIDA_BYTES
    app.config["JSON_AS_ASCII"] = False
    os.environ.setdefault("AUDIT_LOG", str(aj.REGISTROS_DIR / "auditoria.log"))
    aj.REGISTROS_DIR.mkdir(parents=True, exist_ok=True)

    from . import db, eventos, seguridad, servicios
    from .rutas_cliente import bp as bp_cliente
    from .rutas_publicas import bp as bp_publico
    from .rutas_staff import bp as bp_staff

    if aj.DB_PATH.exists():
        db.crear_esquema(aj.DB_PATH, aj.SCHEMA)      # actualiza una BD de una versión anterior (agrega columnas/tablas)
    app.teardown_appcontext(db.cerrar_db)
    app.register_blueprint(bp_publico)
    app.register_blueprint(bp_cliente)
    app.register_blueprint(bp_staff)
    app.jinja_env.filters["mxn"] = servicios.dinero

    @app.before_request
    def _antes():
        if request.endpoint == "static":
            return
        seguridad.cargar_sesion()
        seguridad.verificar_csrf()

    @app.context_processor
    def _contexto():
        u = g.get("usuario")
        n_carrito = 0
        if u is not None and u["role"] == "CLIENTE":
            n_carrito = db.get_db().execute("SELECT COUNT(*) c FROM cart_items WHERE user_id = ?", (u["id"],)).fetchone()["c"]
        return {"usuario": u, "csrf_token": g.sesion["csrf_token"] if g.get("sesion") is not None else "",
                "tiene_permiso": seguridad.tiene_permiso, "avisos": seguridad.avisos, "n_carrito": n_carrito,
                "CATEGORIAS": servicios.CATEGORIAS, "FORMATOS": servicios.FORMATOS}

    @app.after_request
    def _despues(resp):
        resp = seguridad.poner_cookie(resp)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'none'; object-src 'none'; "
                                                   "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # Gestión segura de errores: mensajes genéricos al usuario, detalle solo en el servidor/bitácora
    def _error(codigo, titulo, texto):
        return render_template("error.html", codigo=codigo, titulo=titulo, texto=texto), codigo

    @app.errorhandler(400)
    def _e400(_e):
        return _error(400, "Solicitud no válida", "No pudimos procesar la solicitud.")

    @app.errorhandler(403)
    def _e403(_e):
        return _error(403, "Acceso denegado", "No tienes permiso para realizar esta acción.")

    @app.errorhandler(404)
    def _e404(_e):
        return _error(404, "No encontrado", "El recurso solicitado no existe.")

    @app.errorhandler(405)
    def _e405(_e):
        return _error(405, "Método no permitido", "Esa operación no está disponible.")

    @app.errorhandler(413)
    def _e413(_e):
        return _error(413, "Archivo demasiado grande", "El archivo excede el tamaño permitido.")

    @app.errorhandler(500)
    def _e500(e):
        try:
            g.db.rollback() if "db" in g else None
            eventos.registrar("INTERNAL_ERROR", "ERROR", f"ruta={request.path} tipo={type(getattr(e, 'original_exception', e)).__name__}")
        except Exception:
            pass
        return _error(500, "Error interno", "Ocurrió un problema. El incidente quedó registrado.")

    return app
