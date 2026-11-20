"""Genera la PKI con OpenSSL dentro de certs/  (funciona en Windows, Linux y Mac; no necesita bash).

    python generar_pki.py                      -> para pruebas en una sola computadora
    python generar_pki.py 192.168.1.50         -> con la IP REAL del servidor (dos computadoras)

Crea:  ca.crt / ca.key         Autoridad Certificadora (ca.crt se copia al cliente; ca.key NUNCA)
       server.crt / server.key certificado legítimo del servidor, firmado por la CA
       rogue_server.*          certificado firmado por una CA FALSA   (debe ser rechazado)
       expired.*               certificado CADUCADO                   (debe ser rechazado)
       wronghost.*             certificado de OTRO nombre             (debe ser rechazado)
"""
import os
import shutil
import subprocess
import sys

import config

CONFIG_SSL = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
[ca]
default_ca = CA_default
[CA_default]
dir = .
database = index.txt
new_certs_dir = .
serial = serial.txt
default_md = sha256
policy = pol
unique_subject = no
[pol]
commonName = supplied
organizationName = optional
countryName = optional
"""


def buscar_openssl():
    ruta = shutil.which("openssl")
    if ruta:
        return ruta
    for r in (r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe",
              r"C:\Program Files (x86)\Git\mingw64\bin\openssl.exe", r"C:\Program Files (x86)\Git\usr\bin\openssl.exe"):
        if os.path.exists(r):
            return r
    sys.exit("No encontré OpenSSL. Instala Git for Windows (https://git-scm.com) o OpenSSL y vuelve a intentar.")


def main(ip_servidor="127.0.0.1", nombre_dns="servidor.local"):
    openssl = buscar_openssl()
    os.makedirs(config.CERTS, exist_ok=True)
    for f in os.listdir(config.CERTS):                 # regenerar todo (se conserva la clave del host SSH)
        if not f.startswith("ssh_"):
            os.remove(os.path.join(config.CERTS, f))

    def ossl(*args):
        r = subprocess.run([openssl] + list(args), cwd=config.CERTS, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"Falló: openssl {' '.join(args)}\n{r.stderr}")

    def escribir(nombre, texto):
        with open(config.cert(nombre), "w") as f:
            f.write(texto)

    escribir("openssl.cnf", CONFIG_SSL)
    escribir("index.txt", "")
    escribir("serial.txt", "01\n")
    san = f"DNS:{nombre_dns},DNS:localhost,IP:127.0.0.1,IP:{ip_servidor}"
    ext = ("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
           "extendedKeyUsage=serverAuth\nsubjectAltName={}\nsubjectKeyIdentifier=hash\n"
           "authorityKeyIdentifier=keyid,issuer\n")

    def crear_ca(nombre, cn):
        ossl("genrsa", "-out", nombre + ".key", "2048")
        ossl("req", "-x509", "-new", "-config", "openssl.cnf", "-key", nombre + ".key", "-sha256", "-days", "3650",
             "-subj", f"/O=Org Demo/CN={cn}", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
             "-out", nombre + ".crt")

    def crear_cert(nombre, cn, san_ext, ca, caducado=False):
        ossl("genrsa", "-out", nombre + ".key", "2048")
        ossl("req", "-new", "-config", "openssl.cnf", "-key", nombre + ".key", "-subj", f"/O=Org Demo/CN={cn}",
             "-out", nombre + ".csr")
        escribir(nombre + ".ext", ext.format(san_ext))
        if caducado:   # 'openssl ca' permite fijar fechas pasadas
            ossl("ca", "-config", "openssl.cnf", "-batch", "-notext", "-cert", ca + ".crt", "-keyfile", ca + ".key",
                 "-in", nombre + ".csr", "-out", nombre + ".crt", "-extfile", nombre + ".ext",
                 "-startdate", "20200101000000Z", "-enddate", "20200102000000Z")
        else:
            ossl("x509", "-req", "-in", nombre + ".csr", "-CA", ca + ".crt", "-CAkey", ca + ".key", "-CAcreateserial",
                 "-days", "365", "-sha256", "-extfile", nombre + ".ext", "-out", nombre + ".crt")

    print("[1/5] CA raiz (Org Demo Root CA)")
    crear_ca("ca", "Org Demo Root CA")
    print("[2/5] Certificado legitimo del servidor, firmado por la CA")
    crear_cert("server", nombre_dns, san, "ca")
    print("[3/5] CA falsa + certificado firmado por ella (no confiable)")
    crear_ca("rogue_ca", "Rogue CA")
    crear_cert("rogue_server", nombre_dns, san, "rogue_ca")
    print("[4/5] Certificado caducado (firmado por la CA legitima)")
    crear_cert("expired", nombre_dns, san, "ca", caducado=True)
    print("[5/5] Certificado valido pero de OTRO nombre")
    crear_cert("wronghost", "otro.example.com", "DNS:otro.example.com", "ca")

    for f in os.listdir(config.CERTS):                 # limpiar archivos temporales
        if f.endswith((".csr", ".ext", ".srl", ".old", ".attr", ".pem")) or f in ("index.txt", "serial.txt", "openssl.cnf"):
            os.remove(config.cert(f))
    ossl("verify", "-CAfile", "ca.crt", "server.crt")
    print(f"\nListo. Archivos en: {config.CERTS}\nCopia SOLO certs/ca.crt a la computadora cliente (nunca ca.key ni server.key).")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1")
