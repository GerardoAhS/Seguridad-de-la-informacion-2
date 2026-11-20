# Arquitectura de seguridad

## 1. Visión general

```
                         INTERNET / red no confiable
   Cliente (navegador) ───── HTTPS · TLS ≥ 1.2 · cert. de la CA local ─────▶ ┌──────────────────────────────┐
   Administrador remoto ──── VPN (acceso remoto) ─▶ SSH :2222 ─────────────▶ │  Servidor de aplicación      │
   Sucursal ────────────── VPN sitio a sitio / IPSec túnel (simulado) ─────▶ │  Flask · sesiones · RBAC     │
                                                                             │  cripto · fingerprint        │
                                                                             └───────┬───────────┬──────────┘
                                                                                     │           │
                                                                  SQLite (BD + security_events)  productos/*.enc (AES-256-GCM)
                                                                  respaldos/ (zip + manifiesto firmado)
```
Zonas: **pública** (catálogo, login) · **cliente** (compras, descargas) · **operación** (catálogo, pedidos) ·
**administración** (usuarios, eventos, sesiones; entra por VPN + SSH). Las claves privadas viven fuera del repositorio y de la BD.

## 2. Servicios de seguridad → mecanismos

| Servicio | Mecanismo | Amenaza que cubre |
|---|---|---|
| Confidencialidad | TLS (tránsito); AES-256-GCM (productos en reposo); hash de contraseñas | Espionaje de red; robo de disco/respaldo |
| Integridad | SHA-256 de productos; AES-GCM autentica; firma de comprobantes; manifiesto firmado en respaldos | Alteración de archivos, comprobantes o respaldos |
| Disponibilidad | Respaldo/restauración verificados; bloqueo de cuentas; límite de subida (20 MB) | Pérdida de datos, fuerza bruta |
| Autenticación | Argon2id/scrypt + sal; sesiones aleatorias del servidor; certificados TLS para el servidor | Suplantación de usuario y de servidor |
| Autorización | RBAC con deniega-por-defecto; verificación de propiedad del objeto (órdenes, comprobantes, descargas) | Escalada de privilegios, IDOR |
| No repudio | Firma RSA-PSS del comprobante con clave privada que solo tiene el servidor | "Yo no compré eso" / comprobante falsificado |
| Auditoría | `security_events` (inmutable por triggers) + `auditoria.log` | Falta de trazabilidad, borrado de huellas |

## 3. Criptografía usada (todo con bibliotecas estándar; nada implementado a mano)

| Uso | Algoritmo | Dónde |
|---|---|---|
| Hash de archivos | SHA-256 | `cripto.sha256_*` |
| Contraseñas | Argon2id (o scrypt N=2¹⁵,r=8,p=1) con sal única | `seguridad.hash_password` |
| Productos en reposo | AES-256-GCM, nonce de 96 bits aleatorio por archivo | `cripto.cifrar` |
| Firma de comprobantes | RSA-3072, PSS, SHA-256, JSON canónico | `cripto.firmar` |
| Autenticidad del fingerprint | HMAC-SHA-256 (7 bytes) | `fingerprint.crear_carga` |
| Tokens de sesión / recuperación | `secrets.token_urlsafe(32)`; solo se guarda su SHA-256 | `seguridad`, `rutas_publicas` |
| Certificados TLS | RSA-2048 / SHA-256, CA local, SAN con `localhost`, 127.0.0.1 e IP | `infraestructura/generar_pki.py` |

**Gestión de claves.** `claves_privadas/` (permisos 0600, fuera de Git): `firma_privada.pem`, `productos.key`, `fingerprint.key`.
Opcional: `FIRMA_PASSPHRASE` cifra la clave de firma. Se comparte únicamente `claves_publicas/` (verificación de firmas y `ca.crt`).
Rotación: generar nuevo par y conservar la pública anterior (`key_id` en cada comprobante indica con cuál verificar).

## 4. Sesiones y aplicación web (Unidad 5)
Cookie `sid` HttpOnly + Secure + SameSite=Lax; sesión en BD (se puede revocar); inactividad 30 min (configurable) y tope absoluto de 8 h;
rotación al autenticar; CSRF por sesión en todo POST; CSP (`script-src 'none'`), X-Frame-Options, nosniff, HSTS, `Cache-Control: no-store`;
consultas parametrizadas; Jinja con autoescape; errores genéricos (sin trazas); redirecciones `next` solo relativas; subidas con lista blanca,
verificación de contenido real y nombre saneado; mensajes de login/recuperación que no revelan si el correo existe.

## 5. Fingerprinting (Unidad 3)
Huella de 160 bits = versión | usuario | orden | producto | HMAC. No es el nombre del archivo: va **dentro del contenido**.

| Tipo | Técnica | Imperceptibilidad | Robustez | Límite |
|---|---|---|---|---|
| .txt / .md | Caracteres Unicode de ancho cero, ~12 copias | Invisible al leer | Sobrevive a recortes, copiar-pegar y renombrado | Se pierde si se normaliza/limpia el Unicode |
| .png | LSB en RGB, trama repetida + voto mayoritario | PSNR ≈ 54 dB | Tolera 2 % de ruido y re-guardado PNG | Se pierde con JPEG/reescalado/captura |
| .pdf | Texto invisible (render mode 3) por página | Invisible | Sobrevive a renombrado y extracción de texto | Se pierde al imprimir a imagen/OCR |

Es **disuasión y trazabilidad**, no DRM: un atacante que conozca la técnica puede intentar eliminarla. El HMAC impide *incriminar a otro*.

## 6. Infraestructura de comunicaciones (módulo `infraestructura/`)
- **TLS/PKI**: CA local → certificado del servidor; el cliente valida cadena, vigencia y nombre. Casos negativos probados: CA falsa, caducado, otro nombre, cliente sin la CA.
- **SSH**: usuario no-root, AAA con la BD de la tienda, permisos por comando y registro de cada operación. *Recomendado en producción* (`sshd_config`): `PermitRootLogin no`, `PasswordAuthentication no` (solo claves), `AllowUsers` del grupo de administración, `MaxAuthTries 3`, `X11Forwarding no`, y el puerto 22/2222 accesible **solo desde la VPN**.
- **VPN de acceso remoto**: autentica a una persona y limita recursos por rol (el administrador entra a la red de gestión; el cliente nunca).
- **VPN sitio a sitio + IPSec túnel (ESP)**: une la sucursal con la central; los gateways se autentican entre sí; anti-replay.
- **IPSec en modo transporte**: entre el servidor de aplicación y el de base de datos si estuvieran en hosts separados.
- Estas piezas son **simulaciones** de laboratorio (ver `docs/README_modulo_AAA_original.md`).

## 7. Respaldo y recuperación
Instantánea consistente de SQLite + productos cifrados + `manifest.json` (SHA-256 de cada archivo) + `manifest.sig` (firma RSA-PSS).
La restauración **verifica antes de tocar nada**, no sobrescribe sin `--forzar` y comprueba al final integridad de la BD y que cada producto descifra con su hash.
Las claves se respaldan aparte y fuera de línea.
