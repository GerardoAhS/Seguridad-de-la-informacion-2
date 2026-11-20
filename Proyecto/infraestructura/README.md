# Infraestructura de comunicaciones seguras de una pequeña organización

Aplicación en Python que representa la infraestructura de comunicaciones de una organización y demuestra
que **TLS, PKI, SSH, IPSec y las VPN protegen cosas distintas**.

| Mecanismo | ¿Real o simulado? |
|---|---|
| TLS + certificados digitales | **Real** (módulo `ssl` + OpenSSL) |
| PKI: CA propia y certificados firmados | **Real** (OpenSSL, lo ejecuta `generar_pki.py`) |
| SSH: autenticación, autorización, registro | **Real** (protocolo SSH con `paramiko`) |
| IPSec (ESP, transporte, túnel, anti-replay) | **Simulado**: los paquetes IP son objetos de Python, pero el cifrado es real (AES-GCM) |
| VPN de acceso remoto y VPN sitio a sitio | **Simuladas**: gateways en software que usan el ESP de `ipsec_sim.py` |

## 1. Archivos

| Archivo | Para qué sirve |
|---|---|
| `main.py` | Menú principal para ejecutar todas las demostraciones |
| `generar_pki.py` | Crea con OpenSSL la CA, el certificado del servidor y 3 certificados "malos" para pruebas |
| `server.py` / `client.py` | Aplicación cliente-servidor en modo **plano** o **TLS** |
| `ssh_server.py` / `ssh_client.py` | Administración remota por SSH |
| `ipsec_sim.py` | IPSec simulado: modo transporte, modo túnel y anti-replay |
| `vpn_sim.py` | VPN de acceso remoto y VPN sitio a sitio |
| `aaa.py` | **Autenticación** (usuarios y contraseñas con hash) y **autorización** (roles y permisos) |
| `auditoria.py` | **Registro**: escribe `auditoria.log` con todos los eventos relevantes |
| `test_seguridad.py` | 31 pruebas automáticas de seguridad |
| `config.py` | Puertos, rutas e IP del servidor |

## 2. Arquitectura

```
                 INTERNET (un atacante puede capturar todo lo que pasa)
 CLIENTE ──────────────── TLS 8443 / plano 8080 ───────────────▶ SERVIDOR
    │      ──────────────── SSH 2222 (administración) ─────────▶   │  server.py, ssh_server.py
    │                                                              │
    │  ca.crt (ancla de confianza)               certificado server.crt firmado por la CA
    ▼                                                              ▼
  valida cadena, fechas y nombre              aaa.py (¿quién eres? ¿qué puedes hacer?) + auditoria.log

 VPN ACCESO REMOTO:  usuario ──ESP túnel──▶ [Gateway VPN] ──▶ recursos internos (según el rol)
 VPN SITIO A SITIO:  LAN Sucursal 192.168.10.0/24 ─[GW]══ESP túnel══[GW]─ LAN Central 10.0.0.0/24
```

**Usuarios de laboratorio**

| Usuario | Contraseña | Rol | Puede |
|---|---|---|---|
| `admin_sistemas` | `claveSegura123` | administrador | todo |
| `admin_red` | `rootpass` | administrador | todo |
| `devops_lead` | `passwordSeguro456` | operador | SSH: `status`, `view-logs` (no `restart-service`). Sin VPN |
| `carlos_rrhh` | `rrhh2026` | rrhh | VPN: Nóminas y Portal de Empleados. Sin SSH |
| `ana_finanzas` | `finanzas2026` | finanzas | VPN: Contable, Base de Datos Bancaria y Portal. Sin SSH |

## 3. Instalación

Requiere Python 3.9 o superior y OpenSSL (en Windows lo trae *Git for Windows*).

```
py -m pip install -r requirements.txt
py generar_pki.py          # crea la carpeta certs/  (una sola computadora)
py main.py                 # menú principal
```
En Linux/Mac usa `python3` en lugar de `py`.

## 4. Ejecución

### 4.1 Todo en una computadora
Usa el menú (`py main.py`), o directamente:
```
py ipsec_sim.py            # demostración IPSec
py vpn_sim.py              # demostración de las dos VPN
py -m pytest -v            # las 31 pruebas
```

### 4.2 Cliente y servidor en computadoras diferentes (requerimiento 1)
1. **En el servidor**: `py generar_pki.py 192.168.1.50` (poner la IP **real** del servidor; queda dentro del certificado).
2. **Copiar al cliente solo `certs/ca.crt`** (en la carpeta `certs/` del proyecto del cliente). Nunca `ca.key` ni `server.key`.
3. Abrir en el firewall del servidor los puertos **8080, 8443 y 2222**.
4. **Servidor**: `py server.py plano` y, en otra terminal, `py server.py tls`.
5. **Cliente**: `py client.py plano --host 192.168.1.50` y `py client.py tls --host 192.168.1.50`.
   Con Wireshark (`tcp.port == 8080 || tcp.port == 8443`) se ve la contraseña en claro en el 8080 y solo datos cifrados en el 8443.
6. Certificados malos: en el servidor `py server.py tls --cert certs/expired.crt --key certs/expired.key`
   (también `rogue_server` y `wronghost`); el cliente debe **rechazarlos**.
7. **SSH**: servidor `py ssh_server.py`; cliente `py ssh_client.py 192.168.1.50`.

También se puede fijar la IP con la opción 8 del menú.

## 5. Qué hace cada mecanismo

**TLS.** Cifra y protege la integridad de una sesión cliente-servidor y autentica al **servidor** con su certificado.
El cliente comprueba (a) que el certificado esté firmado por una CA en la que confía, (b) que esté vigente y (c) que el nombre
o la IP coincida con el certificado; si algo falla, aborta **antes de enviar la contraseña**.

**PKI y cadena de confianza.** `generar_pki.py` crea con OpenSSL una CA raíz (`ca.crt`) que firma `server.crt`. El cliente
solo conoce `ca.crt`: confía en cualquier certificado firmado por esa CA y rechaza los demás. Los certificados de prueba
(CA falsa, caducado, nombre distinto) demuestran que cada falla se detecta.

**SSH.** Administración remota **cifrada**. Autentica al usuario (contraseña con hash), restringe quién puede entrar
(permiso `ssh:login`), restringe qué comandos puede ejecutar cada rol y registra cada intento y operación.

**IPSec (ESP).** Protege **paquetes IP** en la capa de red, sin que las aplicaciones lo noten.
- *Modo transporte*: cifra solo el contenido; la cabecera IP original queda visible. Sirve **host a host**.
- *Modo túnel*: cifra el paquete **completo** y le agrega una cabecera IP nueva (de gateway a gateway). Oculta las redes internas.
- *Anti-replay*: cada paquete lleva un número de secuencia; una ventana deslizante rechaza repetidos y muy viejos. Se verifica la integridad **antes** de registrar la secuencia, para que un paquete falso no pueda bloquear los legítimos.

**VPN de acceso remoto.** Autentica a una **persona**. La sesión es temporal, recibe una IP virtual y el gateway comprueba
**cada petición** contra el rol: conectarse a la VPN **no** da acceso a todo (carlos, de RR. HH., llega a Nóminas pero recibe 403 en Contabilidad).

**VPN sitio a sitio.** Une dos **redes**. Se autentican los **gateways** entre sí (clave precompartida), el túnel es permanente
y los equipos de cada LAN no hacen login. Solo se protege el tráfico que coincide con los **selectores** (las subredes); lo demás sale sin túnel.

**Autenticación, autorización y registro.** `autenticar()` = ¿quién eres?; `autorizar()` = ¿qué puedes hacer?; `registrar()` = qué pasó.
Se registran conexiones, accesos permitidos y rechazados, operaciones administrativas, replays y certificados rechazados.

## 6. Diferencias entre los mecanismos

| Mecanismo | Capa | Protege | Autentica a | Alcance |
|---|---|---|---|---|
| TLS | Transporte / aplicación | Una sesión cliente-servidor | El servidor (certificado) | Una aplicación |
| SSH | Aplicación | Administración remota | El usuario | Comandos en un equipo |
| IPSec transporte | Red | El contenido entre dos hosts | Los hosts | Host a host |
| IPSec túnel | Red | El paquete completo entre gateways | Los gateways | Red a red |
| VPN acceso remoto | Red / gateway | Usuario hacia la red privada | **La persona** | Recursos según su rol |
| VPN sitio a sitio | Red | Dos LAN enteras | **Los gateways** | Subredes completas |

## 7. Pruebas de seguridad (`py -m pytest -v`)

| Prueba | Resultado esperado |
|---|---|
| Comunicación plana | La contraseña se ve en claro con un espía de red |
| Comunicación con TLS | No se ve nada legible; TLS 1.2/1.3 |
| Certificado firmado por nuestra CA | Se acepta |
| Certificado de CA falsa / caducado / de otro nombre | El cliente lo rechaza (`CERTIFICADO_RECHAZADO`) |
| Cliente sin la CA | Rechaza incluso el certificado legítimo |
| Cliente `--inseguro` | Acepta un certificado falso (muestra el riesgo de MITM) |
| 401 / 403 / 200 sobre TLS | Autenticación distinta de autorización |
| SSH usuario autorizado | Entra y ejecuta comandos, queda en el log |
| SSH: contraseña mala, usuario inexistente, usuario válido sin permiso SSH | Acceso denegado y registrado |
| SSH comando no permitido al rol | Código 126 y `OPERACION_ADMIN RECHAZADO` |
| IPSec transporte | IP original visible, contenido cifrado |
| IPSec túnel | IP internas ocultas, cabecera nueva de gateways |
| Replay y paquete alterado | Rechazados y registrados |
| Ventana anti-replay | Acepta desorden dentro de la ventana, rechaza repetidos y viejos |
| VPN remota | 200 en recursos del rol, **403** en los demás, 404 sin ruta |
| VPN: login malo, usuario sin permiso de VPN, replay, sesión caducada | 401 / 403 / rechazado / 401 |
| Sitio a sitio | Sin login, cifrado en Internet, selectores, PSK distinta rechazada, replay descartado |

## 8. Limitaciones de seguridad

- **IPSec y las VPN son simulaciones**: no hay IKE real ni interfaces de red virtuales; los paquetes son objetos de Python y las claves se crean en memoria.
- El intercambio de claves de la VPN sitio a sitio está simplificado (PSK + nonces) y no hay renegociación de claves (*rekeying*).
- **La PKI es de laboratorio**: `ca.key` sin contraseña, sin CA intermedia, sin revocación (CRL/OCSP) y sin certificado de cliente (mTLS).
- Las contraseñas son fijas y están en el código (solo para laboratorio); no hay doble factor ni bloqueo de cuentas por intentos fallidos.
- SSH usa contraseña (no claves públicas) y el cliente confía en la huella del servidor la primera vez (TOFU); los comandos son simulados.
- La bitácora es un archivo de texto sin firma ni protección contra modificación.
- No hay protección contra denegación de servicio ni límites de conexiones.
- La VPN de acceso remoto se simula en un mismo proceso; en la realidad el canal de control iría por la red y también tendría que ir protegido con TLS.
