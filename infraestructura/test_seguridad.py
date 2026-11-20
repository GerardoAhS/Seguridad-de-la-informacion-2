"""PRUEBAS DE SEGURIDAD (requerimiento 9).      Ejecutar:  python -m pytest -v
Cada prueba levanta el servidor que necesita en esta misma computadora (puerto aleatorio)."""
import socket
import ssl
import threading
import time

import paramiko
import pytest

import aaa
import config
import ssh_client
import ssh_server
from auditoria import leer
from client import consultar
from ipsec_sim import ErrorIntegridad, ErrorReplay, VentanaReplay, crear_par, Paquete
from server import Servidor
from vpn_sim import (ErrorAutenticacionGateway, ErrorVPN, GatewayAccesoRemoto, GatewaySitio, Internet)

CA = config.cert("ca.crt")
CARLOS = ("carlos_rrhh", "rrhh2026")


@pytest.fixture(autouse=True)
def bitacora_limpia(tmp_path, monkeypatch):
    """Cada prueba usa su propia bitácora, así se puede comprobar qué se registró."""
    monkeypatch.setenv("AUDIT_LOG", str(tmp_path / "auditoria.log"))
    monkeypatch.setenv("AUDIT_SILENCIO", "1")


@pytest.fixture(scope="session", autouse=True)
def certificados():
    if not __import__("os").path.exists(CA):
        import generar_pki
        try:
            generar_pki.main()
        except SystemExit as e:
            pytest.skip(f"No se pudieron generar los certificados: {e}")


def en_log(*fragmentos):
    """¿Hay una línea de la bitácora que contenga TODOS los fragmentos?"""
    return any(all(f in linea for f in fragmentos) for linea in leer())


class Espia:
    """Proxy que registra los bytes que pasan: hace el papel de Wireshark entre cliente y servidor."""

    def __init__(self, puerto_destino):
        self.destino, self.datos = ("127.0.0.1", puerto_destino), bytearray()
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.puerto = self.srv.getsockname()[1]
        threading.Thread(target=self._aceptar, daemon=True).start()

    def _aceptar(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            s = socket.create_connection(self.destino)
            threading.Thread(target=self._copiar, args=(c, s), daemon=True).start()
            threading.Thread(target=self._copiar, args=(s, c), daemon=True).start()

    def _copiar(self, origen, destino):
        try:
            while True:
                trozo = origen.recv(4096)
                if not trozo:
                    break
                self.datos += trozo
                destino.sendall(trozo)
        except OSError:
            pass
        finally:
            for x in (origen, destino):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


# ============ 1-3. TLS, certificados y cadena de confianza ============
def servidor_tls(cert="server"):
    return Servidor("tls", "127.0.0.1", 0, config.cert(cert + ".crt"), config.cert(cert + ".key")).iniciar()


def test_sin_proteccion_la_contrasena_viaja_en_claro():
    srv = Servidor("plano", "127.0.0.1").iniciar()
    espia = Espia(srv.puerto)
    codigo, _, _ = consultar("127.0.0.1", espia.puerto, *CARLOS, "publico", modo="plano")
    assert codigo == 200
    assert b"rrhh2026" in espia.datos            # un atacante en la red LEE la contraseña
    srv.detener()


def test_con_tls_el_trafico_no_se_puede_leer():
    srv = servidor_tls()
    espia = Espia(srv.puerto)
    codigo, _, info = consultar("127.0.0.1", espia.puerto, *CARLOS, "publico", "tls", CA)
    assert codigo == 200
    assert b"rrhh2026" not in espia.datos and b"Boletin" not in espia.datos
    assert info["version"] in ("TLSv1.2", "TLSv1.3") and info["emisor"] == "Org Demo Root CA"
    srv.detener()


def test_certificado_firmado_por_nuestra_ca_se_acepta():
    srv = servidor_tls()
    codigo, _, info = consultar("127.0.0.1", srv.puerto, *CARLOS, "publico", "tls", CA, nombre="servidor.local")
    assert codigo == 200 and info["sujeto"] == "servidor.local"
    srv.detener()


@pytest.mark.parametrize("cert, motivo", [
    ("rogue_server", "unable to get local issuer"),    # firmado por una CA que el cliente no conoce
    ("expired", "expired"),                            # caducado
    ("wronghost", "mismatch"),                         # nombre distinto
])
def test_certificados_no_confiables_son_rechazados(cert, motivo):
    srv = servidor_tls(cert)
    with pytest.raises(ssl.SSLCertVerificationError) as e:
        consultar("127.0.0.1", srv.puerto, *CARLOS, "publico", "tls", CA)
    assert motivo in e.value.verify_message
    assert en_log("CERTIFICADO_RECHAZADO")
    time.sleep(0.3)
    assert en_log("TLS_HANDSHAKE_FALLIDO")             # el servidor también lo registra
    srv.detener()


def test_servidor_sigue_vivo_despues_de_un_handshake_fallido():
    srv = servidor_tls("expired")
    for _ in range(2):
        with pytest.raises(ssl.SSLCertVerificationError):
            consultar("127.0.0.1", srv.puerto, *CARLOS, "publico", "tls", CA)
    srv.detener()


def test_sin_la_ca_ni_el_certificado_legitimo_es_confiable():
    srv = servidor_tls()
    with pytest.raises(ssl.SSLCertVerificationError):
        consultar("127.0.0.1", srv.puerto, *CARLOS, "publico", "tls", None)
    srv.detener()


def test_cliente_inseguro_acepta_certificado_falso_riesgo_de_mitm():
    srv = servidor_tls("rogue_server")
    codigo, _, _ = consultar("127.0.0.1", srv.puerto, *CARLOS, "publico", "tls", None, inseguro=True)
    assert codigo == 200
    srv.detener()


# ============ 8. autenticación vs autorización ============
def test_autenticacion_y_autorizacion_son_cosas_distintas():
    srv = servidor_tls()
    args = ("127.0.0.1", srv.puerto)
    assert consultar(*args, "carlos_rrhh", "mala", "publico", "tls", CA)[0] == 401      # no sabemos quién es
    assert consultar(*args, "ana_finanzas", "finanzas2026", "nomina", "tls", CA)[0] == 403   # es ella, pero no puede
    assert consultar(*args, "carlos_rrhh", "rrhh2026", "nomina", "tls", CA)[0] == 200
    assert en_log("ACCESO_RECHAZADO", "usuario=ana_finanzas") and en_log("ACCESO_PERMITIDO", "usuario=carlos_rrhh")
    assert en_log("AUTENTICACION", "usuario=carlos_rrhh", "resultado=RECHAZADO")
    srv.detener()


# ============ 4. SSH ============
@pytest.fixture
def ssh(tmp_path):
    srv = ssh_server.ServidorSSH("127.0.0.1", 0, str(tmp_path / "ssh_host_key")).iniciar()
    yield srv
    srv.detener()


def test_ssh_usuario_autorizado_ejecuta_comandos(ssh):
    codigo, salida, _ = ssh_client.ejecutar_una_vez("127.0.0.1", ssh.puerto, "admin_sistemas", "claveSegura123", "status")
    assert codigo == 0 and "activo" in salida
    assert en_log("SSH_CONEXION") and en_log("AUTENTICACION", "usuario=admin_sistemas", "resultado=OK")
    assert en_log("OPERACION_ADMIN", "usuario=admin_sistemas", "recurso=status", "resultado=OK")


@pytest.mark.parametrize("usuario, clave", [
    ("admin_sistemas", "incorrecta"),       # contraseña mala
    ("shaja", "123"),                       # usuario inexistente
    ("carlos_rrhh", "rrhh2026"),            # existe y su clave es correcta, pero NO está autorizado para SSH
])
def test_ssh_acceso_no_autorizado_es_rechazado_y_registrado(ssh, usuario, clave):
    with pytest.raises(paramiko.AuthenticationException):
        ssh_client.ejecutar_una_vez("127.0.0.1", ssh.puerto, usuario, clave, "status")
    assert en_log(f"usuario={usuario}", "RECHAZADO")


def test_ssh_usuario_autenticado_pero_sin_permiso_queda_registrado_como_autorizacion(ssh):
    with pytest.raises(paramiko.AuthenticationException):
        ssh_client.ejecutar_una_vez("127.0.0.1", ssh.puerto, "carlos_rrhh", "rrhh2026", "status")
    assert en_log("AUTENTICACION", "usuario=carlos_rrhh", "resultado=OK")          # autenticación OK
    assert en_log("ACCESO_RECHAZADO", "usuario=carlos_rrhh", "permiso=ssh:login")  # autorización NO


def test_ssh_permisos_por_comando_segun_rol(ssh):
    codigo, _, error = ssh_client.ejecutar_una_vez("127.0.0.1", ssh.puerto, "devops_lead", "passwordSeguro456", "restart-service")
    assert codigo == 126 and "Permiso denegado" in error                            # operador no puede reiniciar
    codigo, salida, _ = ssh_client.ejecutar_una_vez("127.0.0.1", ssh.puerto, "admin_sistemas", "claveSegura123", "restart-service")
    assert codigo == 0 and "reiniciado" in salida                                   # administrador sí
    assert en_log("OPERACION_ADMIN", "usuario=devops_lead", "RECHAZADO")
    assert en_log("OPERACION_ADMIN", "usuario=admin_sistemas", "recurso=restart-service", "resultado=OK")


def test_ssh_varios_comandos_en_la_misma_sesion(ssh):
    c = ssh_client.conectar("127.0.0.1", ssh.puerto, "admin_sistemas", "claveSegura123")
    assert ssh_client.ejecutar(c, "status")[0] == 0
    assert ssh_client.ejecutar(c, "view-logs")[0] == 0
    assert ssh_client.ejecutar(c, "borrar-todo")[0] == 127                          # comando inexistente
    c.close()


# ============ 5. IPSec ============
PKT = Paquete("192.168.10.50", "10.0.0.15", b"SECRETO: transferir $1000")


def test_ipsec_modo_transporte_conserva_ip_y_cifra_contenido():
    a, b = crear_par("transporte", "192.168.10.50", "10.0.0.15")
    en_red = a.enviar(PKT)
    assert (en_red.src, en_red.dst, en_red.proto) == ("192.168.10.50", "10.0.0.15", "ESP")   # IP original visible
    assert b"SECRETO" not in en_red.datos                                                    # contenido cifrado
    assert b.recibir(en_red) == PKT


def test_ipsec_modo_tunel_oculta_las_ip_internas_y_agrega_cabecera_nueva():
    a, b = crear_par("tunel", "200.50.10.1", "200.50.20.2")
    en_red = a.enviar(PKT)
    assert (en_red.src, en_red.dst) == ("200.50.10.1", "200.50.20.2")                        # IP de los gateways
    assert b"SECRETO" not in en_red.datos and b"192.168.10.50" not in en_red.datos           # IP internas ocultas
    assert b.recibir(en_red) == PKT


def test_ipsec_replay_es_detectado_y_rechazado():
    a, b = crear_par("tunel", "200.50.10.1", "200.50.20.2")
    capturado = a.enviar(PKT)
    assert b.recibir(capturado) == PKT                    # la primera vez es legítimo
    with pytest.raises(ErrorReplay):
        b.recibir(capturado)                              # el atacante lo reenvía
    assert en_log("IPSEC_REPLAY_RECHAZADO")


def test_ipsec_paquete_alterado_es_rechazado():
    a, b = crear_par("tunel", "200.50.10.1", "200.50.20.2")
    p = a.enviar(PKT)
    p.datos = p.datos[:-1] + bytes([p.datos[-1] ^ 1])
    with pytest.raises(ErrorIntegridad):
        b.recibir(p)
    assert en_log("IPSEC_ICV_INVALIDO")


def test_ventana_anti_replay_acepta_desorden_pero_no_repetidos_ni_viejos():
    v = VentanaReplay(4)
    resultado = []
    for seq in (10, 12, 11, 11, 5, 13):
        ok = v.es_valida(seq)
        if ok:
            v.marcar(seq)
        resultado.append(ok)
    # el 11 llega tarde pero dentro de la ventana: se acepta; el 11 repetido y el 5 (muy viejo): rechazados
    assert resultado == [True, True, True, False, False, True]


# ============ 6. VPN de acceso remoto ============
def test_vpn_remota_da_solo_los_recursos_del_rol():
    gw = GatewayAccesoRemoto()
    carlos = gw.conectar(*CARLOS)
    assert carlos.vip.startswith("10.9.0.")
    assert carlos.solicitar("10.0.0.10")[0] == 200       # Servidor de Nóminas: permitido
    assert carlos.solicitar("10.0.0.11")[0] == 403       # Servidor Contable: conectado a la VPN, pero SIN permiso
    assert carlos.solicitar("10.0.0.2")[0] == 403        # Firewall Core
    assert carlos.solicitar("10.0.0.99")[0] == 404       # no existe
    ana = gw.conectar("ana_finanzas", "finanzas2026")
    assert ana.solicitar("10.0.0.11")[0] == 200 and ana.solicitar("10.0.0.10")[0] == 403
    admin = gw.conectar("admin_red", "rootpass")
    assert all(admin.solicitar(ip)[0] == 200 for ip in ("10.0.0.10", "10.0.0.11", "10.0.0.2"))
    assert en_log("VPN_CONEXION", "usuario=carlos_rrhh") and en_log("ACCESO_RECHAZADO", "usuario=carlos_rrhh")


def test_vpn_remota_rechaza_credenciales_malas_y_usuarios_sin_permiso_de_vpn():
    gw = GatewayAccesoRemoto()
    with pytest.raises(ErrorVPN, match="401"):
        gw.conectar("carlos_rrhh", "mala")
    with pytest.raises(ErrorVPN, match="403"):           # autenticado (clave correcta) pero sin autorización de VPN
        gw.conectar("devops_lead", "passwordSeguro456")
    assert en_log("ACCESO_RECHAZADO", "usuario=devops_lead", "vpn:connect")


def test_vpn_remota_detecta_replay_dentro_del_tunel():
    cli = GatewayAccesoRemoto().conectar(*CARLOS)
    assert cli.solicitar("10.0.0.10")[0] == 200
    with pytest.raises(ErrorVPN, match="ErrorReplay"):
        cli.reenviar(cli.ultimo_esp)
    assert en_log("IPSEC_REPLAY_RECHAZADO")


def test_vpn_remota_sesion_caducada():
    cli = GatewayAccesoRemoto(duracion_sesion=-1).conectar(*CARLOS)
    with pytest.raises(ErrorVPN, match="401"):
        cli.solicitar("10.0.0.10")
    assert en_log("VPN_SESION_INVALIDA")


# ============ 7. VPN sitio a sitio ============
@pytest.fixture
def sitios():
    internet = Internet()
    suc = GatewaySitio("GW-Sucursal", "200.50.10.1", "192.168.10.0/24", {"192.168.10.50": "PC"}, internet, b"psk")
    cen = GatewaySitio("GW-Central", "200.50.20.2", "10.0.0.0/24", {"10.0.0.15": "BD CENTRAL"}, internet, b"psk")
    suc.conectar(cen)
    return internet, suc, cen


def test_sitio_a_sitio_no_pide_login_y_viaja_cifrado(sitios):
    internet, suc, _ = sitios
    r = suc.desde_lan(Paquete("192.168.10.50", "10.0.0.15", b"consulta confidencial"))
    assert r.datos == b"BD CENTRAL"                                   # ningún usuario se autenticó
    visto = internet.capturados[0]
    assert (visto.src, visto.dst, visto.proto) == ("200.50.10.1", "200.50.20.2", "ESP")
    assert b"confidencial" not in visto.datos
    assert en_log("S2S_TRAFICO", "usuario=-")                         # se registra el gateway, no una persona


def test_sitio_a_sitio_solo_protege_el_trafico_de_los_selectores(sitios):
    internet, suc, _ = sitios
    suc.desde_lan(Paquete("192.168.10.50", "8.8.8.8", b"consulta web"))
    assert internet.capturados[-1].proto == "TCP"                     # fuera del selector: sin túnel


def test_sitio_a_sitio_rechaza_gateway_con_otra_psk(sitios):
    internet, _, cen = sitios
    with pytest.raises(ErrorAutenticacionGateway):
        GatewaySitio("GW-Falso", "6.6.6.6", "10.66.0.0/24", {}, internet, b"otra").conectar(cen)
    assert en_log("S2S_AUTENTICACION_FALLIDA")


def test_sitio_a_sitio_descarta_replay_y_trafico_fuera_de_selector(sitios):
    internet, suc, _ = sitios
    suc.desde_lan(Paquete("192.168.10.50", "10.0.0.15", b"hola"))
    assert internet.enviar(internet.capturados[0]) is None            # replay descartado
    assert en_log("IPSEC_REPLAY_RECHAZADO")
    falso = suc.ext.enviar(Paquete("172.16.0.9", "10.0.0.15", b"x"))  # origen que no pertenece a la LAN de la sucursal
    assert internet.enviar(falso) is None
    assert en_log("S2S_SELECTOR_RECHAZADO")


# ============ 8. contraseñas ============
def test_las_contrasenas_no_se_guardan_en_claro():
    assert all(b"rrhh2026" not in u["hash"] for u in aaa.USUARIOS.values())
