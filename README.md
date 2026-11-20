# Plataforma segura de venta y distribución de contenido digital

Proyecto final · Seguridad de la Información. Tienda web (Python/Flask + SQLite) que vende libros electrónicos, manuales y
recursos digitales, y que **integra** el módulo de comunicaciones seguras desarrollado en un entregable anterior de la materia
(`infraestructura/`: TLS/PKI, SSH, IPSec y VPN simuladas, AAA y auditoría).

> Los pagos son **simulados**: hay un formulario de tarjeta realista que se valida (Luhn, vencimiento, CVV) pero **no se cobra
> nada y los datos de la tarjeta no se guardan** en ningún lado. IPSec y las VPN de `infraestructura/` son **simulaciones** de laboratorio.

## Funcionalidades principales
- **Catálogo ampliado**: 18 productos en 6 categorías (libros electrónicos, manuales, documentos técnicos, apuntes, guías,
  material educativo), con búsqueda, filtro por categoría y botón "Comprar ahora".
- **Interfaz** estilo librería: papel crema, tipografía Lora (incluida en `aplicacion/static/fuentes`, licencia OFL, funciona sin internet) y portadas de color por categoría. Sin JavaScript: respeta la CSP.
- **Correos dados de alta**: al registrarse se envía un código de 6 dígitos y la cuenta no entra hasta confirmarlo.
- **Recuperar contraseña con token**: "¿Olvidaste tu contraseña?" envía un código de 6 dígitos (y un enlace) de un solo uso,
  con vencimiento de 15 min y límite de 5 intentos.
- **Pago con tarjeta**: si falta un dígito, el dígito verificador no cuadra, la tarjeta venció o el CVV está incompleto,
  el pago queda **"No se pudo completar"** con el motivo. Ver tarjetas de prueba abajo.
- **Verificación estricta de comprobantes**: cualquier cambio invalida (campos agregados o repetidos, `key_id`,
  `algoritmo`, contenido) y además se compara con los registros de la orden (detecta alteraciones de la BD).
- **Rastreo de copias robusto**: detecta el tipo por contenido (aunque el archivo se renombre), acepta UTF-16/BOM,
  busca la huella del PDF también en metadatos, acepta el comprobante `.json`, reconoce el archivo original sin huella
  y avisa cuando la huella se generó con otra clave.
- Una base de datos creada con una versión previa del proyecto se **actualiza sola** al iniciar (agrega columnas y tablas sin perder datos).
  Para agregar los productos de prueba a una base existente: `python scripts/inicializar.py --solo-datos`.

## Instalación y ejecución (3 comandos)

```bash
pip install -r requirements.txt
python scripts/inicializar.py            # claves, CA y certificados TLS, base de datos, usuarios y productos de prueba
python scripts/ejecutar_servidor.py      # https://localhost:5443
```
Requiere Python 3.10+ y OpenSSL (en Windows lo trae *Git for Windows*).

**Después de clonar el repositorio**, la primera vez se usa `python scripts/inicializar.py --reset` en lugar del segundo comando.
El repositorio no incluye las claves privadas, las `.key` de los certificados, la base de datos ni los productos cifrados
(están en `.gitignore`). `--reset` vuelve a crear la CA y los certificados TLS para que coincidan con las claves locales;
después hay que importar el nuevo `certificados/ca.crt` en el navegador. Los certificados regenerados no se deben subir
de nuevo al repositorio.
Para evitar la advertencia del navegador, importa `certificados/ca.crt` como **autoridad de confianza** (es la CA local del proyecto).
Sin `argon2-cffi` las contraseñas usan **scrypt** (el sistema lo detecta solo); con él usan **Argon2id**.

**Usuarios de prueba**

| Rol | Correo | Contraseña |
|---|---|---|
| ADMINISTRADOR | admin@tienda.test | Admin-Prueba-2026 |
| OPERADOR | operador@tienda.test | Operador-Prueba-2026 |
| CLIENTE | ana@tienda.test / luis@tienda.test | Cliente-Prueba-2026 |

## Correo real (confirmación de cuenta y recuperación de contraseña)
1. Crear el archivo `claves_privadas/correo.ini` (esa carpeta no se sube al repositorio) con este formato:
   ```
   SMTP_HOST=smtp.gmail.com
   SMTP_PUERTO=587
   SMTP_SEGURIDAD=starttls
   SMTP_USUARIO=correo@ejemplo.com
   SMTP_CONTRASENA=contraseña-de-aplicación
   SMTP_REMITENTE=Tienda Segura <correo@ejemplo.com>
   ```
2. Con **Gmail** se requiere la verificación en 2 pasos y una **contraseña de aplicación** (no la contraseña normal de la cuenta).
3. Probar con `python scripts/probar_correo.py destino@ejemplo.com` y reiniciar el servidor.

También se pueden dar como variables de entorno (`SMTP_HOST`, `SMTP_PUERTO`, `SMTP_USUARIO`, `SMTP_CONTRASENA`, `SMTP_REMITENTE`).
La conexión usa STARTTLS (o SSL en el puerto 465) verificando el certificado. **Sin configuración**, los correos se
escriben en `registros/correo_simulado.log` (modo laboratorio) y ahí se leen los códigos. Con `DEMO_MOSTRAR_ENLACE=1` el
código de recuperación también aparece en pantalla (**solo para demostraciones**). En *Configuración* el administrador ve
si el SMTP está activo.

## Tarjetas de prueba (pago simulado)
| Tarjeta | Resultado |
|---|---|
| 4242 4242 4242 4242 · 5555 5555 5555 4444 · Amex 3782 822463 10005 | Aprobado |
| 4000 0000 0000 0002 | Declinada por el banco |
| 4000 0000 0000 9995 | Fondos insuficientes |
| 4000 0000 0000 0069 | Vencida según el banco |
| 4242 4242 4242 424 (falta un dígito), 4242 4242 4242 4241 (Luhn) | No se pudo completar el pago |

Cualquier fecha futura (MM/AA) y CVV de 3 dígitos (4 en Amex), con nombre y apellido del titular.

## Rastrear una copia filtrada (ADMINISTRADOR → "Rastrear copia")
Sube el **archivo del producto** que se descargó (no hace falta que conserve su nombre o extensión) o el comprobante `.json`.
Si no se identifica, la pantalla explica la causa: es el original sin huella, la huella fue alterada o generada con otra
`fingerprint.key` (por ejemplo, si se volvió a descomprimir el proyecto y se regeneraron las claves), o el archivo se
convirtió a otro formato (JPG, captura, copiar-pegar el texto en Word).

## Estructura

```
aplicacion/          app Flask: rutas, seguridad (sesiones, CSRF, roles), cripto, fingerprint, respaldo, plantillas
base_de_datos/       schema.sql (7 tablas del documento + receipts, sessions, cart_items, password_resets, settings)
infraestructura/     módulo de comunicaciones seguras del entregable anterior: TLS/PKI, SSH, IPSec, VPN, AAA, auditoría  (ver "Integración")
certificados/        CA local y certificados TLS (las .key NO se versionan)
claves_publicas/     clave pública de firma de comprobantes y ca.crt (lo único que se comparte)
claves_privadas/     NO se versiona: firma RSA, clave AES de productos, clave HMAC del fingerprint
productos/           productos digitales CIFRADOS (.enc)
respaldos/           respaldos .zip firmados
registros/           auditoria.log (compartida con infraestructura/) y correo_simulado.log
evidencias/          resultados_pruebas.md y artefactos generados por las pruebas
scripts/             inicializar, ejecutar_servidor, respaldar, restaurar, correr_pruebas, verificar_comprobante,
                     recuperar_fingerprint, verificar_hash, iniciar_ssh, probar_correo
pruebas/             13 pruebas obligatorias + 30 adicionales
docs/                arquitectura de seguridad, auditoría, matriz de cumplimiento, guion de demostración
```

## Qué hace cada servicio de seguridad (y dónde está)

| Servicio | Implementación | Archivo |
|---|---|---|
| Confidencialidad en tránsito | HTTPS/TLS ≥1.2 con certificado de la CA local | `scripts/ejecutar_servidor.py`, `infraestructura/generar_pki.py` |
| Confidencialidad en reposo | Productos cifrados con AES-256-GCM | `aplicacion/cripto.py` |
| Integridad de archivos | SHA-256 registrado por producto, verificado en cada descarga | `cripto.sha256_archivo`, `servicios.leer_producto` |
| Autenticación | Contraseñas con Argon2id/scrypt, bloqueo por intentos, sesiones del servidor | `aplicacion/seguridad.py` |
| Autorización | Roles CLIENTE / OPERADOR / ADMINISTRADOR con privilegio mínimo; deniega por defecto | `seguridad.PERMISOS` |
| No repudio | Comprobantes firmados con RSA-PSS/SHA-256; verificación con clave pública | `servicios.emitir_comprobante` |
| Trazabilidad / disuasión | Fingerprint invisible por comprador en txt/md, PDF y PNG | `aplicacion/fingerprint.py` |
| Auditoría | `security_events` de solo escritura (triggers) + `auditoria.log` | `aplicacion/eventos.py` |
| Disponibilidad | Respaldo y restauración con manifiesto firmado | `aplicacion/respaldo.py` |
| Administración remota | SSH con los mismos usuarios de la tienda | `aplicacion/puente_aaa.py`, `scripts/iniciar_ssh.py` |

## Integración con el módulo de infraestructura

`infraestructura/` es el módulo del entregable anterior de la materia, con **cambios mínimos**: `config.py` acepta `CERTS_DIR` y `AUDIT_LOG` por
variable de entorno; `aaa.py` agrega los roles `ADMINISTRADOR`/`OPERADOR` y un gancho `PROVEEDOR_EXTERNO`. Resultado:
- **Una sola fuente de identidades**: SSH autentica contra la tabla `users` de la tienda (ADMINISTRADOR todo; OPERADOR solo `status` y `view-logs`; CLIENTE sin SSH).
- **Una sola bitácora**: los eventos de la tienda y los de TLS/SSH/VPN van al mismo `registros/auditoria.log`.
- **Una sola PKI**: la CA local firma el certificado HTTPS de la tienda (y siguen disponibles los certificados "malos" para las pruebas negativas).
- Los usuarios de laboratorio originales (`admin_sistemas`, etc.) siguen funcionando para las demos de VPN/IPSec.

**SHA-256:** `aplicacion/cripto.py` usa `hashlib.sha256` a través de `sha256_bytes()` y `sha256_archivo()`; el resto del sistema
llama a esas dos funciones.

## Pruebas

```bash
python scripts/correr_pruebas.py     # 43 pruebas en un ambiente aislado; escribe evidencias/resultados_pruebas.md
python -m pytest                     # opcional, mismas pruebas con pytest
cd infraestructura && python -m pytest   # las 31 pruebas originales (requieren paramiko y pytest)
```
Cobertura: las 13 pruebas obligatorias del documento (sección 19) y 30 adicionales (CSRF, inyección SQL/XSS, sesiones,
bloqueo, confirmación de correo, recuperación con código, SMTP con STARTTLS, pago con tarjeta sin almacenar datos,
verificación estricta de comprobantes, rastreo de copias renombradas/convertidas, catálogo, aislamiento entre clientes,
subida de archivos, integridad, fingerprint, respaldo alterado, SSH).

## Respaldo y restauración
```bash
python scripts/respaldar.py
python scripts/restaurar.py respaldos/respaldo_XXXX.zip --forzar
```
Las claves de `claves_privadas/` **no** van en el respaldo: deben guardarse aparte y fuera de línea; sin ellas los productos cifrados no se abren.

## Límites conocidos
IPSec/VPN simuladas · pagos simulados (sin cobro real) · SSH por contraseña (no por clave pública) · fingerprint de texto se elimina si se
normaliza Unicode · bloqueo por cuenta permite bloquear a una víctima · ver `docs/auditoria_hallazgos.md`.
