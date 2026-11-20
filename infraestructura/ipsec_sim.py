"""SIMULACIÓN DE IPSec (protocolo ESP): modo TRANSPORTE, modo TÚNEL y protección ANTI-REPLAY.

Los paquetes IP son objetos de Python (simulado), pero el cifrado SÍ es real: AES-GCM.
Paquete ESP =  SPI | número de secuencia | IV | datos cifrados + ICV (etiqueta de integridad)

  - TRANSPORTE: se cifra solo el contenido. La cabecera IP original (origen/destino) sigue VISIBLE.
  - TÚNEL     : se cifra el paquete COMPLETO y se le pone una cabecera IP NUEVA (de gateway a gateway).
  - ANTI-REPLAY: cada paquete lleva un número de secuencia; uno repetido o muy viejo se rechaza.

    python ipsec_sim.py      (demostración)
"""
import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from auditoria import registrar


@dataclass
class Paquete:
    src: str
    dst: str
    datos: bytes
    proto: str = "TCP"

    def __str__(self):
        if self.proto == "ESP":
            vista = self.datos[:14].hex() + "... (cifrado)"
        else:
            vista = "'" + self.datos.decode(errors="replace") + "'"
        return f"[IP] {self.src} -> {self.dst} | proto={self.proto} | datos={vista}"


class ErrorIPSec(Exception):
    pass


class ErrorReplay(ErrorIPSec):
    pass


class ErrorIntegridad(ErrorIPSec):
    pass


class VentanaReplay:
    """Ventana deslizante anti-replay (idea del RFC 4303): recuerda las últimas 'tamano' secuencias."""

    def __init__(self, tamano=64):
        self.tamano, self.maximo, self.mapa = tamano, 0, 0   # bit 0 del mapa = secuencia 'maximo'

    def es_valida(self, seq):                                # NO modifica la ventana
        if seq == 0:
            return False
        if seq > self.maximo:
            return True
        dif = self.maximo - seq
        return dif < self.tamano and not (self.mapa >> dif) & 1   # False si es demasiado vieja o ya vista

    def marcar(self, seq):
        if seq > self.maximo:
            self.mapa = ((self.mapa << (seq - self.maximo)) | 1) & ((1 << self.tamano) - 1)
            self.maximo = seq
        else:
            self.mapa |= 1 << (self.maximo - seq)


class SA:
    """Asociación de seguridad (en una dirección): SPI, clave, modo y contadores."""

    def __init__(self, spi, clave, modo, tunel_origen=None, tunel_destino=None):
        if modo not in ("transporte", "tunel"):
            raise ValueError("modo debe ser 'transporte' o 'tunel'")
        self.spi, self.clave, self.modo = spi, clave, modo
        self.tunel_origen, self.tunel_destino = tunel_origen, tunel_destino
        self.seq = 0                       # contador del que ENVÍA
        self.ventana = VentanaReplay()     # ventana del que RECIBE


def proteger(pkt, sa):
    """Aplica ESP a un paquete (lado emisor)."""
    sa.seq += 1
    if sa.modo == "transporte":
        interior = {"proto": pkt.proto, "datos": pkt.datos.hex()}
        src, dst = pkt.src, pkt.dst                         # cabecera original visible
    else:
        interior = {"src": pkt.src, "dst": pkt.dst, "proto": pkt.proto, "datos": pkt.datos.hex()}
        src, dst = sa.tunel_origen, sa.tunel_destino        # cabecera NUEVA: se ocultan las IP internas
    cabecera = struct.pack("!II", sa.spi, sa.seq)           # SPI + secuencia (se autentican, no se cifran)
    iv = os.urandom(12)
    cifrado = AESGCM(sa.clave).encrypt(iv, json.dumps(interior).encode(), cabecera)
    return Paquete(src, dst, cabecera + iv + cifrado, "ESP")


def abrir(esp, sa):
    """Verifica y descifra un paquete ESP (lado receptor)."""
    if esp.proto != "ESP" or len(esp.datos) < 8 + 12 + 16:
        raise ErrorIPSec("no es un paquete ESP valido")
    spi, seq = struct.unpack("!II", esp.datos[:8])
    if spi != sa.spi:
        raise ErrorIPSec("SPI desconocido")
    if not sa.ventana.es_valida(seq):                       # 1) ¿secuencia repetida o muy vieja?
        raise ErrorReplay(f"secuencia {seq} repetida o fuera de ventana")
    try:                                                    # 2) verificar integridad (ICV) y descifrar
        claro = AESGCM(sa.clave).decrypt(esp.datos[8:20], esp.datos[20:], esp.datos[:8])
    except InvalidTag:
        raise ErrorIntegridad("ICV invalido: paquete alterado o clave incorrecta") from None
    sa.ventana.marcar(seq)                                  # 3) solo ahora se registra la secuencia
    interior = json.loads(claro)
    datos = bytes.fromhex(interior["datos"])
    if sa.modo == "transporte":
        return Paquete(esp.src, esp.dst, datos, interior["proto"])
    return Paquete(interior["src"], interior["dst"], datos, interior["proto"])


class ExtremoIPSec:
    """Un extremo (host o gateway): SA de salida + SA de entrada + registro de eventos de seguridad."""

    def __init__(self, nombre, sa_salida, sa_entrada):
        self.nombre, self.sa_salida, self.sa_entrada = nombre, sa_salida, sa_entrada

    def enviar(self, pkt):
        return proteger(pkt, self.sa_salida)

    def recibir(self, esp):
        try:
            return abrir(esp, self.sa_entrada)
        except ErrorReplay as e:
            registrar("IPSEC_REPLAY_RECHAZADO", recurso=self.nombre, resultado="RECHAZADO", detalle=str(e))
            raise
        except ErrorIntegridad as e:
            registrar("IPSEC_ICV_INVALIDO", recurso=self.nombre, resultado="RECHAZADO", detalle=str(e))
            raise


def crear_par(modo, ip_a, ip_b, nombre_a="A", nombre_b="B", clave_ab=None, clave_ba=None):
    """Crea los dos extremos con sus claves compartidas. En el modo túnel ip_a/ip_b son las IP de los gateways."""
    clave_ab, clave_ba = clave_ab or os.urandom(32), clave_ba or os.urandom(32)
    spi_ab, spi_ba = int.from_bytes(os.urandom(4), "big") | 0x100, int.from_bytes(os.urandom(4), "big") | 0x100
    ab = SA(spi_ab, clave_ab, modo, ip_a, ip_b)
    ba = SA(spi_ba, clave_ba, modo, ip_b, ip_a)
    ab_rx = SA(spi_ab, clave_ab, modo, ip_a, ip_b)
    ba_rx = SA(spi_ba, clave_ba, modo, ip_b, ip_a)
    return ExtremoIPSec(nombre_a, ab, ba_rx), ExtremoIPSec(nombre_b, ba, ab_rx)


def demo():
    original = Paquete("192.168.10.50", "10.0.0.15", b"Transferir $1000 a cuenta X")
    print("=" * 66 + "\n      SIMULACION DE IPSEC (ESP) Y PROTECCION ANTI-REPLAY\n" + "=" * 66)
    print("\nPaquete original de la aplicacion:\n  ", original)

    print("\n--- MODO TRANSPORTE (host a host) ---")
    a, b = crear_par("transporte", original.src, original.dst, "host-A", "host-B")
    en_red = a.enviar(original)
    print("Lo que ve un atacante en la red:\n  ", en_red)
    print("  -> origen y destino REALES visibles; el contenido va cifrado")
    print("Lo que recibe el destino:\n  ", b.recibir(en_red))

    print("\n--- MODO TUNEL (gateway a gateway) ---")
    a, b = crear_par("tunel", "200.50.10.1", "200.50.20.2", "gateway-A", "gateway-B")
    en_red = a.enviar(original)
    print("Lo que ve un atacante en la red:\n  ", en_red)
    print("  -> las IP internas (192.168.x / 10.x) quedaron OCULTAS dentro del paquete cifrado")
    print("Lo que entrega el gateway receptor:\n  ", b.recibir(en_red))

    print("\n--- ANTI-REPLAY: el atacante reenvia el paquete capturado ---")
    try:
        b.recibir(en_red)
    except ErrorReplay as e:
        print("  RECHAZADO (replay):", e)

    print("\n--- INTEGRIDAD: el atacante modifica un byte ---")
    nuevo = a.enviar(original)
    nuevo.datos = nuevo.datos[:-1] + bytes([nuevo.datos[-1] ^ 1])
    try:
        b.recibir(nuevo)
    except ErrorIntegridad as e:
        print("  RECHAZADO (alterado):", e)

    print("\n--- VENTANA ANTI-REPLAY con secuencias [10, 11, 12, 11, 5, 13] ---")
    v = VentanaReplay(4)
    for s in (10, 11, 12, 11, 5, 13):
        ok = v.es_valida(s)
        if ok:
            v.marcar(s)
        print(f"  secuencia {s:>2}: {'APROBADA' if ok else 'RECHAZADA (repetida o muy vieja)'}")


if __name__ == "__main__":
    demo()
