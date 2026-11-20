import os
import subprocess
import sys

import config

PYTHON = sys.executable


def limpiar_pantalla():
  os.system("cls" if os.name == "nt" else "clear")


def mostrar_menu():
  print("=" * 68)
  print("       SISTEMA DE INFRAESTRUCTURA DE COMUNICACIONES SEGURAS")
  print("=" * 68)
  print(f" IP del servidor que usan los clientes: {config.ip_servidor()}")
  print("-" * 68)
  print("  [1] TLS y certificados (plano vs TLS, certificados malos)")
  print("  [2] Administracion remota SSH (servidor / cliente)")
  print("  [3] IPSec (modo transporte, modo tunel y anti-replay)")
  print("  [4] VPNs (acceso remoto con privilegios y sitio a sitio)")
  print("  [5] Ver registros de auditoria (auditoria.log)")
  print("  [6] Ejecutar TODAS las pruebas automaticas (pytest)")
  print("  [7] Generar certificados (CA + servidor + casos negativos)")
  print("  [8] Configurar la IP del servidor (para usar 2 computadoras)")
  print("  [9] Salir")
  print("=" * 68)


def ejecutar(args):
  """Ejecuta un script de Python. Ctrl+C detiene un servidor y regresa al menu."""
  print("\n[EJECUTANDO] python " + " ".join(args) + "\n" + "-" * 60)
  try:
    subprocess.run([PYTHON] + args, cwd=config.CARPETA)
  except KeyboardInterrupt:
    print("\n[detenido]")
  print("\n" + "-" * 60)
  input("Presiona Enter para regresar al menu principal...")


def hay_certificados():
  if os.path.exists(config.cert("ca.crt")):
    return True
  print("\n[!] Aun no existen los certificados. Usa primero la opcion 7.")
  input("Presiona Enter para continuar...")
  return False


def menu_tls():
  print("\n--- TLS: abre DOS terminales. En una el SERVIDOR y en la otra el CLIENTE ---")
  print("  [a] Servidor SIN proteccion (plano, puerto 8080)")
  print("  [b] Servidor con TLS (puerto 8443)")
  print("  [c] Servidor TLS con certificado de una CA FALSA   (el cliente debe rechazarlo)")
  print("  [d] Servidor TLS con certificado CADUCADO          (el cliente debe rechazarlo)")
  print("  [e] Servidor TLS con certificado de OTRO NOMBRE    (el cliente debe rechazarlo)")
  print("  [f] Cliente plano")
  print("  [g] Cliente TLS (valida el certificado con certs/ca.crt)")
  print("  [h] Cliente TLS sin confiar en nuestra CA (rechaza hasta el certificado legitimo)")
  print("  [i] Cliente TLS --inseguro (NO valida: demuestra el riesgo)")
  op = input("Opcion: ").strip().lower()
  if op in "bcdeghi" and op and not hay_certificados():
    return
  malos = {"c": "rogue_server", "d": "expired", "e": "wronghost"}
  if op == "a":
    ejecutar(["server.py", "plano"])
  elif op == "b":
    ejecutar(["server.py", "tls"])
  elif op in malos:
    ejecutar(["server.py", "tls", "--cert", f"certs/{malos[op]}.crt", "--key", f"certs/{malos[op]}.key"])
  elif op == "f":
    ejecutar(["client.py", "plano"])
  elif op == "g":
    ejecutar(["client.py", "tls"])
  elif op == "h":
    ejecutar(["client.py", "tls", "--sin-ca"])
  elif op == "i":
    ejecutar(["client.py", "tls", "--inseguro"])


def ver_logs():
  print("\n" + "=" * 60 + "\n       REGISTROS DE AUDITORIA (auditoria.log)\n" + "=" * 60)
  if os.path.exists(config.LOG_FILE):
    with open(config.LOG_FILE, "r", encoding="utf-8") as f:
      print(f.read())
  else:
    print("Aun no hay registros generados.")
  input("Presiona Enter para regresar al menu principal...")


def main():
  while True:
    limpiar_pantalla()
    mostrar_menu()
    opcion = input("Ingrese una opcion (1-9): ").strip()
    if opcion == "1":
      menu_tls()
    elif opcion == "2":
      print("\nUsuarios SSH: admin_sistemas/claveSegura123 (todo), devops_lead/passwordSeguro456 (solo status y view-logs),")
      print("              carlos_rrhh/rrhh2026 (autenticado pero SIN permiso SSH)")
      sub = input("Servidor SSH ('s') o Cliente SSH ('c')? [s/c]: ").strip().lower()
      if sub == "s":
        ejecutar(["ssh_server.py"])
      elif sub == "c":
        ejecutar(["ssh_client.py"])
    elif opcion == "3":
      ejecutar(["ipsec_sim.py"])
    elif opcion == "4":
      ejecutar(["vpn_sim.py"])
    elif opcion == "5":
      ver_logs()
    elif opcion == "6":
      if hay_certificados():
        ejecutar(["-m", "pytest", "-v"])
    elif opcion == "7":
      ip = input("IP real del servidor [Enter = 127.0.0.1, una sola computadora]: ").strip() or "127.0.0.1"
      ejecutar(["generar_pki.py", ip])
    elif opcion == "8":
      ip = input("IP del computadora SERVIDOR (ej. 192.168.1.50) [Enter = 127.0.0.1]: ").strip() or "127.0.0.1"
      os.environ["SERVER_IP"] = ip
    elif opcion == "9":
      print("\nSaliendo del sistema de seguridad. Hasta luego!")
      break
    else:
      input("\n[ERROR] Opcion invalida. Presiona Enter para intentar de nuevo.")


if __name__ == "__main__":
  main()
