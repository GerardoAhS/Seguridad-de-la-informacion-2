"""SIMULACIÓN DE VPN: acceso remoto y sitio a sitio (reutiliza ipsec_sim.py para cifrar el túnel).

 VPN DE ACCESO REMOTO : se autentica una PERSONA; la sesión es temporal y cada usuario recibe SOLO los
                        recursos que su rol permite (conectarse a la VPN no da acceso a todo).
 VPN SITIO A SITIO    : se autentican dos GATEWAYS entre sí; el túnel es permanente, transparente para
                        todos los equipos de cada red y se rige por selectores de tráfico (subredes).

    python vpn_sim.py      (demostración)
"""
import hashlib
import hmac
import ipaddress
import os
import secrets
import time

import aaa
from auditoria import registrar
from ipsec_sim import ErrorIPSec, Paquete, crear_par

# Red interna de la oficina central: IP -> recurso
RECURSOS = {
    "10.0.0.10": "Servidor de Nóminas",
    "10.0.0.11": "Servidor Contable",
    "10.0.0.12": "Base de Datos Bancaria",
    "10.0.0.13": "Portal de Empleados",
    "10.0.0.1": "Router Central",
    "10.0.0.2": "Firewall Core",
}


class ErrorVPN(Exception):
    pass


# ======================= VPN DE ACCESO REMOTO =======================
class GatewayAccesoRemoto:
    def __init__(self, ip_publica="198.51.100.1", duracion_sesion=300):
        self.ip_publica, self.duracion = ip_publica, duracion_sesion
        self.sesiones, self._siguiente = {}, 10

    def conectar(self, usuario, password, ip_cliente="203.0.113.50"):
        rol = aaa.autenticar(usuario, password, ip_cliente, "vpn")                          # AUTENTICACIÓN
        if rol is None:
            raise ErrorVPN("401 autenticacion fallida")
        if not aaa.autorizar(usuario, rol, "vpn:connect", ip_cliente, "vpn"):                # AUTORIZACIÓN
            raise ErrorVPN("403 este usuario no tiene permiso de VPN")
        vip = f"10.9.0.{self._siguiente}"                                                    # IP virtual
        self._siguiente += 1
        ext_cliente, ext_gateway = crear_par("tunel", ip_cliente, self.ip_publica, "cliente-vpn", "gateway-vpn")
        token = secrets.token_hex(8)
        self.sesiones[token] = {"usuario": usuario, "rol": rol, "vip": vip, "ext": ext_gateway,
                                "expira": time.time() + self.duracion, "ip": ip_cliente}
        registrar("VPN_CONEXION", usuario, ip_cliente, "vpn", "OK", f"ip_virtual={vip} rol={rol}")
        visibles = [n for n in RECURSOS.values() if aaa.tiene_permiso(rol, "recurso:" + n)]
        return ClienteVPN(self, token, vip, ext_cliente, visibles)

    def procesar(self, token, esp):
        """Recibe un paquete ESP del cliente, decide si ese usuario puede llegar al recurso y responde."""
        s = self.sesiones.get(token)
        if s is None or s["expira"] < time.time():
            self.sesiones.pop(token, None)
            registrar("VPN_SESION_INVALIDA", recurso="vpn", resultado="RECHAZADO", detalle="sesion inexistente o caducada")
            raise ErrorVPN("401 sesion invalida o caducada")
        try:
            interior = s["ext"].recibir(esp)                       # descifra; rechaza replay / alteraciones
        except ErrorIPSec as e:
            raise ErrorVPN(f"paquete rechazado ({type(e).__name__})")
        if interior.src != s["vip"]:
            registrar("VPN_SPOOFING", s["usuario"], s["ip"], "vpn", "RECHAZADO", f"origen falso {interior.src}")
            raise ErrorVPN("IP de origen no corresponde a la sesion")
        recurso = RECURSOS.get(interior.dst)
        if recurso is None:
            registrar("ACCESO_RECHAZADO", s["usuario"], s["ip"], interior.dst, "RECHAZADO", "sin ruta")
            texto = "404 no hay ruta a ese host"
        elif aaa.autorizar(s["usuario"], s["rol"], "recurso:" + recurso, s["ip"], recurso):   # CONTROL POSTERIOR A LA CONEXIÓN
            texto = f"200 Acceso concedido a '{recurso}'"
        else:
            texto = f"403 acceso DENEGADO a '{recurso}' para el rol '{s['rol']}'"
        return s["ext"].enviar(Paquete(interior.dst, s["vip"], texto.encode()))

    def cerrar(self, token):
        s = self.sesiones.pop(token, None)
        if s:
            registrar("VPN_DESCONEXION", s["usuario"], s["ip"], "vpn")


class ClienteVPN:
    def __init__(self, gateway, token, vip, extremo, recursos_visibles):
        self.gateway, self.token, self.vip, self.ext = gateway, token, vip, extremo
        self.recursos_visibles, self.ultimo_esp = recursos_visibles, None

    def solicitar(self, ip_destino, datos="GET /"):
        """Envía una petición por el túnel. Devuelve (código, texto)."""
        self.ultimo_esp = self.ext.enviar(Paquete(self.vip, ip_destino, datos.encode()))
        return self.reenviar(self.ultimo_esp)

    def reenviar(self, esp):
        """Envía un ESP ya construido (sirve para simular el replay de un atacante)."""
        respuesta = self.gateway.procesar(self.token, esp)
        texto = self.ext.recibir(respuesta).datos.decode()
        return int(texto[:3]), texto[4:]

    def desconectar(self):
        self.gateway.cerrar(self.token)


# ======================= VPN SITIO A SITIO =======================
class ErrorAutenticacionGateway(Exception):
    pass


class Internet:
    """Red pública simulada: todo lo que pasa queda en 'capturados' (lo que vería un atacante)."""

    def __init__(self):
        self.nodos, self.capturados = {}, []

    def enviar(self, pkt):
        self.capturados.append(pkt)
        nodo = self.nodos.get(pkt.dst)
        return nodo.recibir_de_internet(pkt) if nodo else None


class GatewaySitio:
    def __init__(self, nombre, ip_wan, red_lan, equipos, internet, psk):
        self.nombre, self.ip_wan, self.lan = nombre, ip_wan, ipaddress.ip_network(red_lan)
        self.equipos, self.internet, self.psk = equipos, internet, psk
        self.ext, self.red_remota = None, None
        internet.nodos[ip_wan] = self

    def conectar(self, otro):
        """Autenticación MUTUA DE GATEWAYS con clave precompartida (PSK), estilo IKE simplificado."""
        na, nb = os.urandom(16), os.urandom(16)                    # nonces aleatorios

        def prueba(psk, quien):                                    # HMAC: demuestra conocer la PSK sin enviarla
            return hmac.new(psk, quien.encode() + na + nb, hashlib.sha256).digest()

        if not (hmac.compare_digest(prueba(self.psk, self.nombre), prueba(otro.psk, self.nombre)) and
                hmac.compare_digest(prueba(self.psk, otro.nombre), prueba(otro.psk, otro.nombre))):
            registrar("S2S_AUTENTICACION_FALLIDA", recurso=f"{self.nombre}<->{otro.nombre}", resultado="RECHAZADO",
                      detalle="la PSK no coincide")
            raise ErrorAutenticacionGateway("los gateways no comparten la misma PSK")
        clave_ab = hmac.new(self.psk, b"A->B" + na + nb, hashlib.sha256).digest()    # claves de sesión derivadas
        clave_ba = hmac.new(self.psk, b"B->A" + na + nb, hashlib.sha256).digest()
        self.ext, otro.ext = crear_par("tunel", self.ip_wan, otro.ip_wan, self.nombre, otro.nombre, clave_ab, clave_ba)
        self.red_remota, otro.red_remota = otro.lan, self.lan
        registrar("S2S_TUNEL_ESTABLECIDO", recurso=f"{self.nombre}<->{otro.nombre}", resultado="OK",
                  detalle=f"selectores {self.lan} <-> {otro.lan}")

    def desde_lan(self, pkt):
        """Un equipo de la LAN envía un paquete. Solo entra al túnel si coincide con el selector."""
        if self.ext and ipaddress.ip_address(pkt.dst) in self.red_remota:
            resp = self.internet.enviar(self.ext.enviar(pkt))
            return self.ext.recibir(resp) if resp else None
        return self.internet.enviar(pkt)       # fuera del selector: sale SIN protección

    def recibir_de_internet(self, esp):
        if not self.ext or esp.proto != "ESP":
            return None
        try:
            interior = self.ext.recibir(esp)
        except ErrorIPSec:
            return None                        # replay o alterado: se descarta (ya quedó registrado)
        if ipaddress.ip_address(interior.src) not in self.red_remota or ipaddress.ip_address(interior.dst) not in self.lan:
            registrar("S2S_SELECTOR_RECHAZADO", recurso=self.nombre, resultado="RECHAZADO",
                      detalle=f"{interior.src} -> {interior.dst} fuera de los selectores")
            return None
        registrar("S2S_TRAFICO", recurso=f"{interior.src}->{interior.dst}", detalle=f"entregado por {self.nombre} (sin usuario)")
        respuesta = self.equipos.get(interior.dst, "sin respuesta")
        return self.ext.enviar(Paquete(interior.dst, interior.src, respuesta.encode()))


# ======================= DEMOSTRACIÓN =======================
def demo():
    print("=" * 66 + "\n      VPN DE ACCESO REMOTO (autentica a la PERSONA)\n" + "=" * 66)
    gw = GatewayAccesoRemoto()
    for usuario, clave in (("carlos_rrhh", "rrhh2026"), ("ana_finanzas", "finanzas2026"), ("admin_red", "rootpass")):
        print(f"\n>>> {usuario} se conecta desde Internet")
        cli = gw.conectar(usuario, clave)
        print(f"    VPN establecida. IP virtual {cli.vip}. Recursos que su rol permite: {cli.recursos_visibles}")
        for ip in ("10.0.0.10", "10.0.0.11", "10.0.0.2"):
            codigo, texto = cli.solicitar(ip)
            print(f"    acceso a {ip} ({RECURSOS[ip]}): {codigo} {texto}")
        cli.desconectar()
    print("\n>>> Contraseña incorrecta y usuario sin permiso de VPN:")
    for u, c in (("carlos_rrhh", "mala"), ("devops_lead", "passwordSeguro456")):
        try:
            gw.conectar(u, c)
        except ErrorVPN as e:
            print(f"    {u}: {e}")

    print("\n" + "=" * 66 + "\n      VPN SITIO A SITIO (autentica a los GATEWAYS)\n" + "=" * 66)
    internet = Internet()
    sucursal = GatewaySitio("GW-Sucursal", "200.50.10.1", "192.168.10.0/24", {"192.168.10.50": "PC de ventas"}, internet, b"psk-de-laboratorio")
    central = GatewaySitio("GW-Central", "200.50.20.2", "10.0.0.0/24", {"10.0.0.15": "Servidor de base de datos: sincronizacion OK"}, internet, b"psk-de-laboratorio")
    sucursal.conectar(central)
    resp = sucursal.desde_lan(Paquete("192.168.10.50", "10.0.0.15", b"Solicitud de sincronizacion"))
    print("\nLa PC 192.168.10.50 (sin ningun login) recibe del servidor 10.0.0.15:", resp.datos.decode())
    print("Lo que ve un atacante en Internet:\n  ", internet.capturados[0])
    print("\nTrafico hacia 8.8.8.8 (fuera del selector) viaja SIN tunel:")
    sucursal.desde_lan(Paquete("192.168.10.50", "8.8.8.8", b"consulta web"))
    print("  ", internet.capturados[-1])
    print("\nUn gateway impostor con otra PSK intenta unirse:")
    try:
        GatewaySitio("GW-Falso", "6.6.6.6", "10.66.0.0/24", {}, internet, b"otra-psk").conectar(central)
    except ErrorAutenticacionGateway as e:
        print("  RECHAZADO:", e)
    print("\nEl atacante reenvia un paquete capturado (replay):")
    internet.enviar(internet.capturados[0])
    print("  -> el gateway lo descarto (ver IPSEC_REPLAY_RECHAZADO en el log)")


if __name__ == "__main__":
    demo()
