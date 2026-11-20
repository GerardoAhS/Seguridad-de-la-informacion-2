"""Registro de eventos de seguridad: tabla security_events + bitácora de archivo compartida con infraestructura/ (auditoria.log)."""
import os
import re
import sys
from pathlib import Path

from flask import has_request_context, g, request

from .db import ahora, get_db

# La bitácora de infraestructura/ (TLS, SSH, VPN, IPSec) y la de la tienda quedan en el MISMO archivo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "infraestructura"))
import auditoria  # noqa: E402

_CONTROL = re.compile(r"[\x00-\x1f\x7f|]")


def limpio(valor, maximo=200):
    """Evita inyección en la bitácora: sin saltos de línea ni separadores en datos que controla el usuario."""
    return _CONTROL.sub(" ", str(valor if valor is not None else ""))[:maximo]


def registrar(evento, resultado="OK", detalle="", email=None, user_id=None, origen=None):
    """Guarda el evento (usuario, evento, fecha/hora, resultado y origen) y hace COMMIT de lo pendiente."""
    if has_request_context():
        usuario = getattr(g, "usuario", None)
        if usuario is not None:
            user_id = user_id if user_id is not None else usuario["id"]
            email = email or usuario["email"]
        origen = origen or request.remote_addr
    email, detalle, origen = limpio(email or "-"), limpio(detalle), limpio(origen or "-", 60)
    con = get_db()
    con.execute("INSERT INTO security_events(user_id, user_email, event, created_at, result, origin, detail) "
                "VALUES(?,?,?,?,?,?,?)", (user_id, email, evento, ahora(), resultado, origen, detalle))
    con.commit()
    os.environ.setdefault("AUDIT_SILENCIO", "1")
    auditoria.registrar(evento, usuario=email, ip=origen, recurso="tienda", resultado=resultado, detalle=detalle)
