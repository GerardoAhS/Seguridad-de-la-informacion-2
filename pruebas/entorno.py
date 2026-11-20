"""Ambiente aislado para las pruebas: directorio temporal propio con claves, CA/certificados, BD y datos de prueba.
No toca la base de datos ni las claves reales del proyecto."""
import atexit
import os
import pathlib
import re
import shutil
import sys
import tempfile

RAIZ = pathlib.Path(__file__).resolve().parent.parent
TMP = pathlib.Path(tempfile.mkdtemp(prefix="tienda_pruebas_"))
atexit.register(lambda: shutil.rmtree(TMP, ignore_errors=True))

os.environ["PROYECTO_RAIZ"] = str(TMP)
os.environ["EVIDENCIAS_DIR"] = str(RAIZ / "evidencias")
os.environ["AUDIT_SILENCIO"] = "1"
os.environ.pop("DB_PATH", None)
sys.path[:0] = [str(RAIZ), str(RAIZ / "infraestructura")]

from aplicacion import cripto, create_app, datos_demo, db  # noqa: E402
from aplicacion.ajustes import Ajustes  # noqa: E402

B = "https://localhost"
AJ = Ajustes()
USUARIOS = {rol: (c, pw) for c, _n, rol, pw in datos_demo.USUARIOS_PRUEBA}
ANA = ("ana@tienda.test", "Cliente-Prueba-2026")
LUIS = ("luis@tienda.test", "Cliente-Prueba-2026")
OPERADOR = ("operador@tienda.test", "Operador-Prueba-2026")
ADMIN = ("admin@tienda.test", "Admin-Prueba-2026")

_app = None


def app():
    global _app
    if _app is None:
        for d in (AJ.CLAVES_DIR, AJ.CLAVES_PUBLICAS_DIR, AJ.CERTS_DIR, AJ.PRODUCTOS_DIR, AJ.RESPALDOS_DIR, AJ.REGISTROS_DIR):
            d.mkdir(parents=True, exist_ok=True)
        cripto.generar_par_firma(AJ.CLAVES_DIR, AJ.CLAVES_PUBLICAS_DIR)
        import config as cfg
        import generar_pki
        cfg.CERTS = str(AJ.CERTS_DIR)
        generar_pki.main("127.0.0.1")
        db.crear_esquema(AJ.DB_PATH, AJ.SCHEMA)
        _app = create_app(AJ)
        with _app.app_context():
            datos_demo.sembrar_usuarios()
            datos_demo.sembrar_productos()
    return _app


def consulta(sql, params=()):
    """Lectura directa de la BD de pruebas (para verificar resultados sin pasar por la aplicación)."""
    import sqlite3
    con = sqlite3.connect(str(AJ.DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def ejecutar(sql, params=()):
    import sqlite3
    con = sqlite3.connect(str(AJ.DB_PATH))
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


def eventos(evento=None, resultado=None, detalle=None):
    sql, p = "SELECT * FROM security_events WHERE 1=1", []
    for campo, v in (("event", evento), ("result", resultado)):
        if v:
            sql += f" AND {campo} = ?"
            p.append(v)
    if detalle:
        sql += " AND detail LIKE ?"
        p.append(f"%{detalle}%")
    return consulta(sql + " ORDER BY id", p)


class Navegador:
    """Simula un navegador HTTPS: guarda cookies y agrega el token CSRF automáticamente."""

    def __init__(self):
        self.c = app().test_client()

    def get(self, url, **kw):
        return self.c.get(url, base_url=B, **kw)

    def token(self):
        r = self.get("/login")
        return re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)

    def post(self, url, data=None, csrf=True, **kw):
        data = dict(data or {})
        if csrf and "csrf_token" not in data:
            data["csrf_token"] = self.token()
        return self.c.post(url, data=data, base_url=B, **kw)

    def login(self, cred):
        return self.post("/login", {"email": cred[0], "password": cred[1]})

    @classmethod
    def como(cls, cred):
        n = cls()
        r = n.login(cred)
        assert r.status_code == 302, f"no se pudo iniciar sesión como {cred[0]}: {r.status_code}"
        return n

    def cookie(self):
        return next((c.value for c in self.c._cookies.values() if c.key == "sid"), None) if hasattr(self.c, "_cookies") else None


TARJETA_OK = {"titular": "Ana Cliente Prueba", "numero": "4242 4242 4242 4242", "vencimiento": "12/30", "cvv": "123"}
TARJETA_DECLINADA = dict(TARJETA_OK, numero="4000 0000 0000 0002")


def comprar(nav, productos=(1, 3, 4), aprobar=True):
    """Flujo completo de compra simulada (formulario de tarjeta de prueba). Devuelve el id de la orden."""
    for pid in productos:
        assert nav.post(f"/carrito/agregar/{pid}").status_code == 302
    r = nav.post("/ordenes")
    assert r.status_code == 302
    oid = int(r.headers["Location"].split("?")[0].rsplit("/", 1)[1])
    r = nav.post(f"/ordenes/{oid}/pagar", TARJETA_OK if aprobar else TARJETA_DECLINADA)
    assert r.status_code == 302
    return oid


def ultimo_correo(para):
    """Último mensaje del buzón simulado dirigido a 'para'."""
    texto = (AJ.REGISTROS_DIR / "correo_simulado.log").read_text(encoding="utf-8")
    bloques = [b for b in texto.split("-" * 70) if f"Para: {para}" in b]
    return bloques[-1] if bloques else ""


def codigo_de_correo(para):
    import re as _re
    return _re.findall(r"\b(\d{6})\b", ultimo_correo(para))[-1]


def registrar(email, nombre="Usuario Prueba", pw="Clave-Segura-2026", confirmar=True):
    """Alta de cuenta + (opcional) confirmación del correo con el código recibido."""
    n = Navegador()
    r = n.post("/registro", {"email": email, "name": nombre, "password": pw, "password2": pw})
    if confirmar and r.status_code == 302:
        n.post("/verificar-correo", {"accion": "confirmar", "email": email, "codigo": codigo_de_correo(email)})
    return r
