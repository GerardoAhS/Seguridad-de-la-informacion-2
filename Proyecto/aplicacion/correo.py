"""Envío de correos (confirmación de cuenta y recuperación de contraseña).

Si hay un servidor SMTP configurado, el correo se envía de verdad (STARTTLS o SSL con verificación de certificado).
Si no, se escribe en registros/correo_simulado.log (modo laboratorio), para que el sistema funcione sin Internet.

Configuración (variables de entorno, o el archivo claves_privadas/correo.ini que NO se versiona):

    SMTP_HOST=smtp.gmail.com
    SMTP_PUERTO=587
    SMTP_SEGURIDAD=starttls          # starttls (puerto 587) o ssl (puerto 465)
    SMTP_USUARIO=tienda.segura.demo@gmail.com
    SMTP_CONTRASENA=xxxx xxxx xxxx xxxx    # en Gmail: "contraseña de aplicación" (requiere verificación en 2 pasos)
    SMTP_REMITENTE=Tienda Segura <tienda.segura.demo@gmail.com>

Los códigos y enlaces NUNCA se escriben en la bitácora de auditoría; solo se registra que se envió (o falló) un correo.
"""
import os
import smtplib
from html import escape
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from flask import current_app

from .db import ahora

CLAVES = ("SMTP_HOST", "SMTP_PUERTO", "SMTP_SEGURIDAD", "SMTP_USUARIO", "SMTP_CONTRASENA", "SMTP_REMITENTE")


def configuracion():
    """Lee la configuración SMTP: primero el archivo correo.ini, y las variables de entorno la sobrescriben."""
    aj = current_app.config["AJUSTES"]
    conf = {}
    ruta = aj.CLAVES_DIR / "correo.ini"
    if ruta.exists():
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if linea and not linea.startswith(("#", ";", "[")) and "=" in linea:
                k, v = linea.split("=", 1)
                conf[k.strip().upper()] = v.split(" #", 1)[0].strip().strip('"')
    for k in CLAVES:
        if os.environ.get(k):
            conf[k] = os.environ[k]
    return conf


def smtp_configurado():
    c = configuracion()
    return bool(c.get("SMTP_HOST") and c.get("SMTP_USUARIO") and c.get("SMTP_CONTRASENA"))


def _mensaje(destinatario, asunto, texto, html, remitente):
    m = EmailMessage()
    m["Subject"] = asunto
    m["From"] = remitente
    m["To"] = destinatario
    m["Message-ID"] = make_msgid(domain=remitente.rsplit("@", 1)[-1].strip("> ") or "tienda.local")
    m.set_content(texto)
    if html:
        m.add_alternative(html, subtype="html")
    return m


def enviar(destinatario, asunto, texto, html=None):
    """Envía el correo. Devuelve 'smtp' si salió por SMTP, 'simulado' si quedó en el buzón local, o lanza la excepción del SMTP."""
    c = configuracion()
    if not smtp_configurado():
        aj = current_app.config["AJUSTES"]
        aj.REGISTROS_DIR.mkdir(parents=True, exist_ok=True)
        with open(aj.REGISTROS_DIR / "correo_simulado.log", "a", encoding="utf-8") as f:
            f.write(f"[{ahora()}] Para: {destinatario} | Asunto: {asunto}\n{texto}\n{'-' * 70}\n")
        return "simulado"
    remitente = c.get("SMTP_REMITENTE") or formataddr(("Tienda Segura", c["SMTP_USUARIO"]))
    msg = _mensaje(destinatario, asunto, texto, html, remitente)
    puerto = int(c.get("SMTP_PUERTO") or 587)
    seguridad = (c.get("SMTP_SEGURIDAD") or ("ssl" if puerto == 465 else "starttls")).lower()
    ctx = ssl.create_default_context()                 # verifica el certificado del servidor de correo
    if seguridad == "ssl":
        with smtplib.SMTP_SSL(c["SMTP_HOST"], puerto, context=ctx, timeout=20) as s:
            s.login(c["SMTP_USUARIO"], c["SMTP_CONTRASENA"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(c["SMTP_HOST"], puerto, timeout=20) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(c["SMTP_USUARIO"], c["SMTP_CONTRASENA"])
            s.send_message(msg)
    return "smtp"


# ---------------------------------------------------------------- plantillas de los correos
def _html(titulo, nombre, cuerpo, codigo, enlace=None, boton=None, vigencia=15):
    nombre, enlace = escape(nombre), escape(enlace, quote=True) if enlace else None
    btn = (f'<p style="margin:24px 0"><a href="{enlace}" style="background:#e63946;color:#fff;padding:12px 22px;'
           f'border-radius:999px;text-decoration:none;font-weight:700">{boton}</a></p>') if enlace else ""
    return f"""<div style="font-family:Segoe UI,Arial,sans-serif;background:#0b1426;padding:28px">
<div style="max-width:520px;margin:auto;background:#13213b;border-radius:16px;overflow:hidden;color:#e8eefc">
<div style="height:14px;background:repeating-linear-gradient(90deg,#e63946 0 26px,#fff 26px 52px)"></div>
<div style="padding:24px 28px"><h2 style="margin:0 0 6px">{titulo}</h2><p>Hola {nombre},</p><p>{cuerpo}</p>
<p style="font-size:34px;letter-spacing:10px;font-weight:800;background:#0b1426;border-radius:12px;padding:14px;
text-align:center;color:#ffbe0b">{codigo}</p>{btn}
<p style="color:#9fb0cf;font-size:13px">Vence en {vigencia} minutos y solo se puede usar una vez.
Si no fuiste tú, ignora este mensaje: nadie podrá usar tu cuenta sin este código.</p></div></div></div>"""


def enviar_codigo_verificacion(email, nombre, codigo, vigencia):
    texto = (f"Hola {nombre},\n\nTu código para confirmar tu correo en Tienda Segura es: {codigo}\n\n"
             f"Vence en {vigencia} minutos y solo se puede usar una vez. Si no creaste una cuenta, ignora este mensaje.")
    return enviar(email, f"Tu código de confirmación: {codigo}", texto,
                  _html("Confirma tu correo", nombre, "Usa este código para activar tu cuenta:", codigo, vigencia=vigencia))


def enviar_codigo_recuperacion(email, nombre, codigo, enlace, vigencia):
    texto = (f"Hola {nombre},\n\nRecibimos una solicitud para restablecer tu contraseña.\n\n"
             f"Tu código (token) de recuperación es: {codigo}\n"
             f"También puedes usar este enlace: {enlace}\n\n"
             f"Vence en {vigencia} minutos y solo se puede usar una vez. Si no lo pediste, ignora este mensaje.")
    return enviar(email, "Recupera tu contraseña · Tienda Segura", texto,
                  _html("Recupera tu contraseña", nombre, "Escribe este código en la página de recuperación:", codigo,
                        enlace, "Restablecer contraseña", vigencia))
