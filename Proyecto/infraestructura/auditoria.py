"""REGISTRO (auditoría): una sola bitácora para TLS, SSH, IPSec y VPN -> auditoria.log"""
import datetime
import os
import threading

import config

_candado = threading.Lock()


def ruta_log():
    return os.environ.get("AUDIT_LOG", config.LOG_FILE)


def registrar(evento, usuario="-", ip="-", recurso="-", resultado="OK", detalle=""):
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = (f"[{ahora}] {evento:<24} | usuario={usuario} | ip={ip} | recurso={recurso} "
             f"| resultado={resultado} | {detalle}").rstrip()
    with _candado:
        with open(ruta_log(), "a", encoding="utf-8") as f:
            f.write(linea + "\n")
    if os.environ.get("AUDIT_SILENCIO") != "1":
        print("   [LOG] " + linea)
    return linea


def leer():
    if not os.path.exists(ruta_log()):
        return []
    with open(ruta_log(), encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f]
