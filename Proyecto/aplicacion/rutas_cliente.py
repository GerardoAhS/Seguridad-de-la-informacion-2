"""Funciones del CLIENTE: carrito, órdenes, pago simulado, comprobantes y descargas con fingerprint."""
import io
import json
import secrets

from flask import Blueprint, abort, g, redirect, render_template, request, send_file, url_for

from .seguridad import avisar as flash
from . import cripto, eventos, seguridad, servicios
from .db import get_db

bp = Blueprint("cliente", __name__)

MIME = {"txt": "text/plain; charset=utf-8", "md": "text/plain; charset=utf-8",
        "pdf": "application/pdf", "png": "image/png"}


def _orden_propia(oid):
    """Una orden solo es visible para su dueño. Para los demás 'no existe' (404) y se registra el intento."""
    o = get_db().execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if o is None or o["user_id"] != g.usuario["id"]:
        if o is not None:
            eventos.registrar("ACCESS_DENIED", "DENEGADO", f"orden ajena id={oid}")
        abort(404)
    return o


# ---------------------------------------------------------------- carrito
@bp.route("/carrito")
@seguridad.requiere("carrito:usar")
def carrito():
    items = get_db().execute("SELECT p.id, p.name, p.price_cents, p.category, p.file_type FROM cart_items c JOIN products p ON p.id = c.product_id "
                             "WHERE c.user_id = ? AND p.status = 'ACTIVO' ORDER BY p.id", (g.usuario["id"],)).fetchall()
    return render_template("carrito.html", items=items, total=sum(i["price_cents"] for i in items))


@bp.route("/carrito/agregar/<int:pid>", methods=["POST"])
@seguridad.requiere("carrito:usar")
def carrito_agregar(pid):
    p = get_db().execute("SELECT id FROM products WHERE id = ? AND status = 'ACTIVO'", (pid,)).fetchone()
    if p is None:
        abort(404)
    get_db().execute("INSERT OR IGNORE INTO cart_items(user_id, product_id) VALUES(?,?)", (g.usuario["id"], pid))
    get_db().commit()
    flash("Producto agregado al carrito.", "ok")
    return redirect(url_for("cliente.carrito"))


@bp.route("/comprar/<int:pid>", methods=["POST"])
@seguridad.requiere("orden:crear")
def comprar_ahora(pid):
    """Botón "Comprar ahora": crea una orden solo con este producto y lleva directo al pago."""
    db = get_db()
    p = db.execute("SELECT id, price_cents FROM products WHERE id = ? AND status = 'ACTIVO'", (pid,)).fetchone()
    if p is None:
        abort(404)
    cur = db.execute("INSERT INTO orders(user_id, total_cents, status, created_at) VALUES(?,?,'PENDIENTE',datetime('now'))",
                     (g.usuario["id"], p["price_cents"]))
    db.execute("INSERT INTO order_items(order_id, product_id, price_cents) VALUES(?,?,?)", (cur.lastrowid, pid, p["price_cents"]))
    db.execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (g.usuario["id"], pid))
    eventos.registrar("ORDER_CREATED", "OK", f"orden={cur.lastrowid} total_centavos={p['price_cents']} (comprar ahora)")
    return redirect(url_for("cliente.orden_detalle", oid=cur.lastrowid))


@bp.route("/carrito/quitar/<int:pid>", methods=["POST"])
@seguridad.requiere("carrito:usar")
def carrito_quitar(pid):
    get_db().execute("DELETE FROM cart_items WHERE user_id = ? AND product_id = ?", (g.usuario["id"], pid))
    get_db().commit()
    return redirect(url_for("cliente.carrito"))


# ---------------------------------------------------------------- órdenes
@bp.route("/ordenes", methods=["GET"])
@seguridad.requiere("orden:ver_propias")
def ordenes():
    filas = get_db().execute("SELECT o.*, (SELECT COUNT(*) FROM order_items i WHERE i.order_id = o.id) AS n FROM orders o "
                             "WHERE o.user_id = ? ORDER BY o.id DESC", (g.usuario["id"],)).fetchall()
    return render_template("ordenes.html", ordenes=filas)


@bp.route("/ordenes", methods=["POST"])
@seguridad.requiere("orden:crear")
def orden_crear():
    db = get_db()
    items = db.execute("SELECT p.id, p.price_cents FROM cart_items c JOIN products p ON p.id = c.product_id "
                       "WHERE c.user_id = ? AND p.status = 'ACTIVO'", (g.usuario["id"],)).fetchall()
    if not items:
        flash("Tu carrito está vacío.", "error")
        return redirect(url_for("cliente.carrito"))
    total = sum(i["price_cents"] for i in items)         # el precio lo decide el SERVIDOR, nunca el formulario
    cur = db.execute("INSERT INTO orders(user_id, total_cents, status, created_at) VALUES(?,?,'PENDIENTE',datetime('now'))",
                     (g.usuario["id"], total))
    oid = cur.lastrowid
    db.executemany("INSERT INTO order_items(order_id, product_id, price_cents) VALUES(?,?,?)",
                   [(oid, i["id"], i["price_cents"]) for i in items])      # precio histórico congelado
    db.execute("DELETE FROM cart_items WHERE user_id = ?", (g.usuario["id"],))
    eventos.registrar("ORDER_CREATED", "OK", f"orden={oid} total_centavos={total}")
    return redirect(url_for("cliente.orden_detalle", oid=oid))


@bp.route("/ordenes/<int:oid>")
@seguridad.requiere("orden:ver_propias")
def orden_detalle(oid):
    o = _orden_propia(oid)
    items = get_db().execute("SELECT p.id, p.name, p.file_type, p.category, i.price_cents FROM order_items i "
                             "JOIN products p ON p.id = i.product_id WHERE i.order_id = ? ORDER BY p.id", (oid,)).fetchall()
    pagos = get_db().execute("SELECT * FROM payments WHERE order_id = ? ORDER BY id", (oid,)).fetchall()
    recibo = get_db().execute("SELECT 1 FROM receipts WHERE order_id = ?", (oid,)).fetchone()
    return render_template("orden.html", o=o, items=items, pagos=pagos, recibo=recibo,
                           resultado=request.args.get("pago"), ultimo=pagos[-1] if pagos else None,
                           tarjetas_prueba=servicios.TARJETAS_PRUEBA)


@bp.route("/ordenes/<int:oid>/pagar", methods=["POST"])
@seguridad.requiere("orden:pagar")
def orden_pagar(oid):
    """PAGO SIMULADO con formulario de tarjeta. Se valida como una pasarela real (Luhn, vencimiento, CVV) pero los datos
    de la tarjeta NO se guardan en ningún lado: solo existen en memoria durante esta petición. No se cobra nada."""
    o = _orden_propia(oid)
    if o["status"] != "PENDIENTE":
        flash("Esta orden ya no admite pago.", "error")
        return redirect(url_for("cliente.orden_detalle", oid=oid))
    aprobado, motivo, marca = servicios.validar_tarjeta(
        request.form.get("titular"), request.form.get("numero"), request.form.get("vencimiento"), request.form.get("cvv"))
    ref = ("TX-" if aprobado else "RX-") + secrets.token_hex(6).upper()
    db = get_db()
    db.execute("INSERT INTO payments(order_id, transaction_reference, amount_cents, status, created_at, detail) "
               "VALUES(?,?,?,?,datetime('now'),?)",
               (oid, ref, o["total_cents"], "APROBADO" if aprobado else "RECHAZADO", "" if aprobado else motivo))
    if not aprobado:
        eventos.registrar("PAYMENT_REJECTED", "RECHAZADO", f"orden={oid} ref={ref} motivo={motivo}")
        flash(f"No se pudo completar el pago. {motivo}", "error")
        return redirect(url_for("cliente.orden_detalle", oid=oid, pago="rechazado"))
    db.execute("UPDATE orders SET status = 'PAGADA' WHERE id = ?", (oid,))
    servicios.emitir_comprobante(oid)
    eventos.registrar("PAYMENT_APPROVED", "OK", f"orden={oid} ref={ref} marca={marca}")
    eventos.registrar("SIGNATURE_CREATED", "OK", f"orden={oid} algoritmo=RSA-PSS-SHA256")
    flash("¡Pago aprobado! Tu comprobante fue firmado digitalmente y tus productos ya están disponibles.", "ok")
    return redirect(url_for("cliente.orden_detalle", oid=oid, pago="aprobado"))


# ---------------------------------------------------------------- comprobantes
@bp.route("/comprobantes")
@seguridad.requiere("comprobante:ver_propios")
def comprobantes():
    filas = get_db().execute("SELECT r.order_id, r.created_at, o.total_cents FROM receipts r JOIN orders o ON o.id = r.order_id "
                             "WHERE o.user_id = ? ORDER BY r.order_id DESC", (g.usuario["id"],)).fetchall()
    return render_template("comprobantes.html", filas=filas)


def _recibo_propio(oid):
    _orden_propia(oid)
    r = get_db().execute("SELECT * FROM receipts WHERE order_id = ?", (oid,)).fetchone()
    if r is None:
        abort(404)
    return r


@bp.route("/comprobantes/<int:oid>")
@seguridad.requiere("comprobante:ver_propios")
def comprobante(oid):
    r = _recibo_propio(oid)
    firma_ok = servicios.comprobante_valido(r)
    datos = json.loads(r["content"])
    diferencias = servicios.diferencias_con_bd(datos) if firma_ok else []
    eventos.registrar("SIGNATURE_VERIFIED", "OK" if firma_ok and not diferencias else "INVALIDA", f"orden={oid} origen=bd")
    return render_template("comprobante.html", r=r, datos=datos, valido=firma_ok and not diferencias,
                           firma_ok=firma_ok, diferencias=diferencias)


@bp.route("/comprobantes/<int:oid>/descargar")
@seguridad.requiere("comprobante:ver_propios")
def comprobante_descargar(oid):
    r = _recibo_propio(oid)
    cuerpo = json.dumps(servicios.comprobante_exportable(r), ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(io.BytesIO(cuerpo), mimetype="application/json", as_attachment=True,
                     download_name=f"comprobante_orden_{oid}.json")


@bp.route("/verificar", methods=["GET", "POST"])
@seguridad.requiere("comprobante:verificar")
def verificar():
    """El cliente sube un comprobante descargado y se verifica su firma con la clave pública."""
    resultado = None
    if request.method == "POST":
        archivo = request.files.get("archivo")
        datos = archivo.read(200_001) if archivo else b""
        if len(datos) > 200_000:
            resultado = {"valido": False, "motivo": "El archivo es demasiado grande para ser un comprobante.", "datos": None, "diferencias": []}
        else:
            doc, error = servicios.leer_documento(datos)
            resultado = ({"valido": False, "motivo": error, "datos": None, "diferencias": []} if error
                         else servicios.analizar_documento(doc))
        eventos.registrar("SIGNATURE_VERIFIED", "OK" if resultado["valido"] else "INVALIDA",
                          f"origen=archivo {resultado['motivo'][:120]}")
    return render_template("verificar.html", resultado=resultado)


# ---------------------------------------------------------------- mis productos y descargas
@bp.route("/mis-productos")
@seguridad.requiere("producto:descargar_propios")
def mis_productos():
    filas = get_db().execute(
        "SELECT o.id AS order_id, p.id AS product_id, p.name, p.file_type, p.category, o.created_at FROM orders o "
        "JOIN order_items i ON i.order_id = o.id JOIN products p ON p.id = i.product_id "
        "WHERE o.user_id = ? AND o.status IN ('PAGADA','COMPLETADA') ORDER BY o.id DESC, p.id", (g.usuario["id"],)).fetchall()
    return render_template("mis_productos.html", filas=filas)


@bp.route("/descargas/<int:oid>/<int:pid>")
@seguridad.requiere("producto:descargar_propios")
def descargar(oid, pid):
    db = get_db()
    o = db.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    autorizado = (o is not None and o["user_id"] == g.usuario["id"] and o["status"] in ("PAGADA", "COMPLETADA")
                  and db.execute("SELECT 1 FROM order_items WHERE order_id = ? AND product_id = ?", (oid, pid)).fetchone())
    if not autorizado:
        eventos.registrar("DOWNLOAD", "DENEGADO", f"orden={oid} producto={pid} (no comprado o no pagado)")
        abort(403)
    p = db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    try:
        copia, huella = servicios.copia_personalizada(p, g.usuario["id"], oid)
    except servicios.ErrorIntegridad as e:
        eventos.registrar("INTEGRITY_FAILURE", "ERROR", f"producto={pid} {e}")
        abort(500)
    db.execute("INSERT INTO downloads(user_id, order_id, product_id, fingerprint, delivered_sha256, ip, created_at) "
               "VALUES(?,?,?,?,?,?,datetime('now'))",
               (g.usuario["id"], oid, pid, huella, cripto.sha256_bytes(copia), request.remote_addr))
    eventos.registrar("FINGERPRINT_CREATED", "OK", f"orden={oid} producto={pid} tipo={p['file_type']}")
    eventos.registrar("DOWNLOAD", "OK", f"orden={oid} producto={pid}")
    return send_file(io.BytesIO(copia), mimetype=MIME[p["file_type"]], as_attachment=True,
                     download_name=servicios.nombre_descarga_seguro(p["download_name"]))
