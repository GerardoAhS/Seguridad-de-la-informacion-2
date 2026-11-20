"""AUTENTICACIÓN (¿quién eres?) y AUTORIZACIÓN (¿qué puedes hacer?).

Las contraseñas de abajo son SOLO de laboratorio. Se guardan como hash (scrypt), no en claro.
"""
import hashlib
import hmac
import os

from auditoria import registrar

# Rol -> permisos. "*" = todo.
ROLES = {
    "administrador": {"*"},
    "operador": {"ssh:login", "ssh:status", "ssh:view-logs", "app:publico"},
    # Roles de la tienda web (la base de datos de aplicacion/ es la fuente de usuarios para SSH)
    "ADMINISTRADOR": {"*"},
    "OPERADOR": {"ssh:login", "ssh:status", "ssh:view-logs"},
    "rrhh": {"vpn:connect", "app:publico", "app:nomina",
             "recurso:Servidor de Nóminas", "recurso:Portal de Empleados"},
    "finanzas": {"vpn:connect", "app:publico",
                 "recurso:Servidor Contable", "recurso:Base de Datos Bancaria",
                 "recurso:Portal de Empleados"},
}

_DATOS = {  # usuario: (contraseña de laboratorio, rol)
    "admin_sistemas": ("claveSegura123", "administrador"),
    "admin_red": ("rootpass", "administrador"),
    "devops_lead": ("passwordSeguro456", "operador"),
    "carlos_rrhh": ("rrhh2026", "rrhh"),
    "ana_finanzas": ("finanzas2026", "finanzas"),
}


def _hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)


USUARIOS = {}
for _u, (_pw, _rol) in _DATOS.items():
    _sal = os.urandom(16)
    USUARIOS[_u] = {"rol": _rol, "sal": _sal, "hash": _hash(_pw, _sal)}


# INTEGRACIÓN: función (usuario, password) -> rol | None que consulta la base de datos de la tienda.
# La instala aplicacion/puente_aaa.py; si es None, solo existen los usuarios de laboratorio de arriba.
PROVEEDOR_EXTERNO = None


def autenticar(usuario, password, ip="-", servicio="app"):
    """AUTENTICACIÓN: devuelve el rol si las credenciales son correctas, o None. Siempre registra."""
    reg = USUARIOS.get(usuario)
    if reg is None and PROVEEDOR_EXTERNO is not None:
        rol_ext = PROVEEDOR_EXTERNO(usuario, password)
        registrar("AUTENTICACION", usuario, ip, servicio, "OK" if rol_ext else "RECHAZADO",
                  f"rol={rol_ext} (BD tienda)" if rol_ext else "credenciales invalidas o usuario inexistente")
        return rol_ext
    calculado = _hash(password, reg["sal"] if reg else b"0" * 16)   # mismo costo aunque el usuario no exista
    ok = reg is not None and hmac.compare_digest(calculado, reg["hash"])
    registrar("AUTENTICACION", usuario, ip, servicio, "OK" if ok else "RECHAZADO",
              f"rol={reg['rol']}" if ok else "credenciales invalidas o usuario inexistente")
    return reg["rol"] if ok else None


def tiene_permiso(rol, permiso):
    permisos = ROLES.get(rol, set())
    return "*" in permisos or permiso in permisos


def autorizar(usuario, rol, permiso, ip="-", recurso=None):
    """AUTORIZACIÓN: ¿este rol puede hacer esto? Registra el acceso permitido o rechazado."""
    ok = tiene_permiso(rol, permiso)
    registrar("ACCESO_PERMITIDO" if ok else "ACCESO_RECHAZADO", usuario, ip, recurso or permiso,
              "OK" if ok else "RECHAZADO", f"rol={rol} permiso={permiso}")
    return ok
