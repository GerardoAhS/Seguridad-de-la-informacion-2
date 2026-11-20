"""Cliente de administración remota (SSH real).   python ssh_client.py [IP_DEL_SERVIDOR]"""
import getpass
import sys

import paramiko

import config


def conectar(host, puerto, usuario, password):
    """Abre la sesión SSH. Lanza paramiko.AuthenticationException si el acceso es denegado."""
    c = paramiko.SSHClient()
    # Confía en la huella del servidor la primera vez (TOFU). En producción se verificaría de antemano.
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=puerto, username=usuario, password=password, look_for_keys=False,
              allow_agent=False, timeout=10, auth_timeout=10, banner_timeout=10)
    return c


def ejecutar(cliente, comando):
    """Devuelve (código, salida, error) de un comando remoto."""
    _, out, err = cliente.exec_command(comando, timeout=10)
    salida, error = out.read().decode(), err.read().decode()
    return out.channel.recv_exit_status(), salida, error


def ejecutar_una_vez(host, puerto, usuario, password, comando):
    c = conectar(host, puerto, usuario, password)
    try:
        return ejecutar(c, comando)
    finally:
        c.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else config.ip_servidor()
    print("=" * 60 + "\n      CLIENTE DE ADMINISTRACION REMOTA (SSH)\n" + "=" * 60)
    usuario = input("login as: ").strip()
    password = getpass.getpass(f"Password for {usuario}: ")
    try:
        print(f"\n[CLIENTE] Conectando a {host}:{config.PUERTO_SSH} ...")
        c = conectar(host, config.PUERTO_SSH, usuario, password)
    except paramiko.AuthenticationException:
        print("\nPermission denied. (usuario/contraseña inválidos, o sin autorización para SSH)")
        return
    except Exception as e:
        print(f"[CLIENTE ERROR] No se pudo conectar: {e}")
        return
    huella = c.get_transport().get_remote_server_key().get_fingerprint().hex(":")
    print(f"[CLIENTE] Sesión establecida. Huella del servidor: {huella}")
    print("Comandos disponibles: status, restart-service, view-logs, exit\n")
    while True:
        cmd = input(f"{usuario}@servidor-remoto:~$ ").strip()
        if cmd == "exit":
            break
        if cmd:
            codigo, salida, error = ejecutar(c, cmd)
            print(salida + error, end="")
    c.close()


if __name__ == "__main__":
    main()
