# Evidencias de pruebas

- Fecha: 2026-11-09 16:44:58
- Python 3.13.18 · Linux
- Resultado global: **43/43 pruebas aprobadas**

## Pruebas mínimas obligatorias (sección 19)

| # | Prueba | Resultado esperado | Estado |
|---|---|---|---|
| 01 | Contraseña incorrecta | Acceso rechazado. | ✅ APROBADA |
| 02 | CLIENTE intenta una función administrativa | Acceso rechazado. | ✅ APROBADA |
| 03 | OPERADOR intenta cambiar roles | Acceso rechazado. | ✅ APROBADA |
| 04 | ADMINISTRADOR autorizado | Operación permitida. | ✅ APROBADA |
| 05 | Certificado TLS correcto | Conexión aceptada. | ✅ APROBADA |
| 06 | Certificado no confiable | Conexión rechazada. | ✅ APROBADA |
| 07 | Comprobante original | Firma digital válida. | ✅ APROBADA |
| 08 | Comprobante modificado | Firma digital inválida. | ✅ APROBADA |
| 09 | Producto descargado | Fingerprint recuperable. | ✅ APROBADA |
| 10 | CLIENTE intenta descargar producto no comprado | Acceso rechazado. | ✅ APROBADA |
| 11 | Archivo original | Hash esperado. | ✅ APROBADA |
| 12 | Archivo modificado | Hash diferente. | ✅ APROBADA |
| 13 | Restauración de respaldo | Información crítica recuperada. | ✅ APROBADA |

### Detalle de lo observado

**01 · Contraseña incorrecta**

```
POST /login con contraseña errónea -> HTTP 401; LOGIN_FAILED registrado. password_hash almacenado empieza con '$argon2id$v=19…' (nunca la contraseña).
```

**02 · CLIENTE intenta una función administrativa**

```
GET a rutas de ADMINISTRADOR/OPERADOR -> /admin/usuarios: 403, /admin/eventos: 403, /admin/sesiones: 403, /operador/productos: 403, /operador/ordenes: 403. Eventos ACCESS_DENIED registrados.
```

**03 · OPERADOR intenta cambiar roles**

```
POST /admin/usuarios/4/rol (rol=ADMINISTRADOR) -> HTTP 403; el rol en la BD sigue siendo CLIENTE.
```

**04 · ADMINISTRADOR autorizado**

```
Consulta usuarios/eventos (200) y cambia el rol de un usuario CLIENTE->OPERADOR (302). Evento ROLE_CHANGED registrado; se revirtió.
```

**05 · Certificado TLS correcto**

```
Cliente que confía en la CA local (ca.crt) -> HTTP 200 sobre TLSv1.3 / TLS_AES_256_GCM_SHA384; encabezado HSTS presente.
```

**06 · Certificado no confiable**

```
firmado por una CA falsa: RECHAZADO (unable to get local issuer certificate)
caducado: RECHAZADO (certificate has expired)
emitido para otro nombre: RECHAZADO (Hostname mismatch, certificate is not valid for 'localhost'.)
legítimo pero el cliente NO confía en la CA local: RECHAZADO (unable to get local issuer certificate)
```

**07 · Comprobante original**

```
Orden #1: la página muestra 'FIRMA VÁLIDA'; verificación externa con la clave pública (RSA-PSS/SHA-256) = True; el cliente también la verifica subiendo el .json. key_id=418974a973bf268c
```

**08 · Comprobante modificado**

```
Orden #2: se cambió el total (8900 -> 1) en el archivo y también en la BD -> la verificación devuelve FIRMA INVÁLIDA en ambos casos.
```

**09 · Producto descargado**

```
Orden #3 de ana (usuario #3):
  .md: huella recuperada -> usuario #3, orden #3, producto #1
  .txt: huella recuperada -> usuario #3, orden #3, producto #2
  .pdf: huella recuperada -> usuario #3, orden #3, producto #3
  .png: huella recuperada -> usuario #3, orden #3, producto #4
  La herramienta del ADMINISTRADOR identificó al comprador a partir de la copia 'filtrada' (PDF).
```

**10 · CLIENTE intenta descargar producto no comprado**

```
Producto comprado -> 200; producto fuera de su orden -> 403; orden de otra persona -> 403; orden sin pagar -> 403. Intentos registrados como DOWNLOAD/DENEGADO.
```

**11 · Archivo original**

```
  producto #1 guia_criptografia.md: SHA-256 440963414a268cd2ed33de2f… == calculado ✔
  producto #2 apuntes_redes_seguras.txt: SHA-256 b336235522bf01bc69cae227… == calculado ✔
  producto #3 manual_seguridad_web.pdf: SHA-256 ac66cc808d4021e8c24dc489… == calculado ✔
  producto #4 infografia_tls.png: SHA-256 872fc66800a24291549dcfd7… == calculado ✔
  producto #5 python_desde_cero.pdf: SHA-256 f0c0221559147a8eba4d0c30… == calculado ✔
  producto #6 estructuras_de_datos.pdf: SHA-256 0176e79de2d38a310cbaf7da… == calculado ✔
  producto #7 manual_git_github.md: SHA-256 93fef8b657ebea514502b0ca… == calculado ✔
  producto #8 manual_hoja_de_calculo.pdf: SHA-256 08dba1f00702b19074130dbf… == calculado ✔
  producto #9 especificacion_api_rest.md: SHA-256 7d921ee12eea83b7a000d0da… == calculado ✔
  producto #10 arquitectura_microservicios.pdf: SHA-256 2cc3d3426cd197eef70ace7d… == calculado ✔
  producto #11 plantilla_requerimientos.txt: SHA-256 4a8098bb43d52b10b4b6c8bf… == calculado ✔
  producto #12 apuntes_bases_de_datos.md: SHA-256 40ec275a11b94a5f837575f8… == calculado ✔
  producto #13 apuntes_calculo_diferencial.txt: SHA-256 6fad81ae378e82e82395a721… == calculado ✔
  producto #14 guia_entrevistas_tecnicas.md: SHA-256 e72b550de6d584cd827b7646… == calculado ✔
  producto #15 guia_comandos_linux.png: SHA-256 059edcb7b27a9995fe07e4f1… == calculado ✔
  producto #16 guia_reporte_investigacion.pdf: SHA-256 217979ae79481bd896a350bd… == calculado ✔
  producto #17 ejercicios_logica_programacion.txt: SHA-256 bb96fb25019d86f488d8aef8… == calculado ✔
  producto #18 infografia_ciclo_de_vida.png: SHA-256 89fc7718f4fd72c66d3dc1d3… == calculado ✔
```

**12 · Archivo modificado**

```
Cambiar 1 carácter: SHA-256 original b336235522bf01bc… vs modificado e0a260399e910a30…
  Alterar 1 bit del .enc en disco -> archivo alterado o ausente (InvalidTag)
```

**13 · Restauración de respaldo**

```
Respaldo respaldo_20261109_164449_072955.zip. Se borraron BD y productos; tras restaurar: integridad_bd=ok, users=4, products=18, orders=6, payments=5, receipts=5, downloads=5, security_events=54, productos_verificados=18. La orden, el comprobante (firma válida) y la descarga funcionan.
```

## Pruebas adicionales de seguridad

| Prueba | Estado |
|---|---|
| registro valida entradas y fuerza rol cliente | ✅ |
| no existe contrasena en claro en la base de datos | ✅ |
| bloqueo por intentos fallidos | ✅ |
| csrf peticion sin token rechazada | ✅ |
| cookie de sesion y encabezados de seguridad | ✅ |
| fijacion de sesion se rota el identificador al autenticar | ✅ |
| admin revoca sesion y el usuario pierde acceso | ✅ |
| desactivar cuenta bloquea acceso y revoca sesiones | ✅ |
| recuperacion de contrasena token unico y con expiracion | ✅ |
| recuperacion con codigo token enviado por correo | ✅ |
| registro exige confirmar el correo | ✅ |
| correo por smtp real con starttls | ✅ |
| cliente no ve ordenes ni comprobantes ajenos | ✅ |
| operador puede gestionar catalogo y pedidos pero no ver eventos | ✅ |
| operador precios historicos y estado de ordenes | ✅ |
| inyeccion sql y xss no prosperan | ✅ |
| bitacora de eventos es de solo escritura | ✅ |
| eventos obligatorios con usuario fecha resultado y origen | ✅ |
| subida de productos valida tipo y cifra en reposo | ✅ |
| producto alterado en disco se detecta al descargar | ✅ |
| fingerprint es distinto por comprador y no se puede forjar | ✅ |
| fingerprint png es imperceptible y tolera ruido leve | ✅ |
| respaldo alterado no se restaura | ✅ |
| ssh usa los usuarios de la tienda con privilegio minimo | ✅ |
| roles matriz de privilegios minimos | ✅ |

### Detalle de las pruebas adicionales

**Registro: validación de entradas**

```
Entradas inválidas rechazadas (400): {'correo inválido': 400, 'contraseña corta': 400, 'sin números': 400, 'no coinciden': 400, 'nombre con etiquetas': 400}. 'role=ADMINISTRADOR' en el alta se ignora (queda CLIENTE). Correo duplicado: mensaje genérico, sin revelar que existe.
```

**Contraseñas solo como hash**

```
Columnas de users: ['id', 'email', 'password_hash', 'name', 'role', 'status', 'created_at', 'last_login', 'email_verified']. Ninguna contraseña de prueba aparece en la BD; ana y luis comparten contraseña pero tienen hashes distintos (sal por usuario).
```

**Bloqueo por intentos fallidos**

```
5 contraseñas erróneas -> la 6ª, aun correcta, recibe HTTP 429 y queda LOGIN_FAILED/BLOQUEADO (ventana de 15 min).
```

**CSRF**

```
POST sin token y con token falso -> HTTP 400; evento CSRF_REJECTED.
```

**Cookie y encabezados**

```
Set-Cookie: sid=JipTzqWc…; Expires=Tue, 10 Nov 2026 07:44:50 GMT;  Max-Age=28800;  Secure;  HttpOnly;  Path
CSP: default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

**Sesiones**

```
Al iniciar sesión se destruye la sesión anónima y se crea otra (anti fijación). En la BD solo se guarda el SHA-256 del token.
```

**Revocar sesiones**

```
El ADMINISTRADOR revoca la sesión de luis; su siguiente petición es redirigida a /login. Evento SESSION_REVOKED.
```

**Desactivar cuenta**

```
Cuenta desactivada: sesiones revocadas y login rechazado; ACCOUNT_DISABLED registrado. El admin no puede desactivarse ni quitarse el rol a sí mismo.
```

**Recuperación de contraseña (enlace)**

```
Respuesta idéntica para correos existentes y no existentes; token aleatorio guardado como hash; un solo uso; vencimiento; la contraseña vieja deja de funcionar; PASSWORD_RESET registrado.
```

**Recuperación con código por correo**

```
Se envía un código (token) de 6 dígitos al correo; en la BD solo queda su hash; un código erróneo -> 400; el correcto cambia la contraseña; no se puede reutilizar; 5 intentos fallidos lo invalidan; pedir otro invalida el anterior.
```

**Alta de correo**

```
Al registrarse se envía un código de 6 dígitos; la cuenta no puede iniciar sesión hasta confirmarlo; un código inválido -> 400; EMAIL_VERIFIED registrado.
```

**Correo saliente por SMTP**

```
Con SMTP_HOST/USUARIO/CONTRASEÑA configurados el código se envía por el servidor de correo usando STARTTLS con verificación de certificado; no queda en el buzón simulado.
```

**Aislamiento entre clientes**

```
luis intenta ver/pagar la orden #7 de ana -> (404, 404, 404, 404) (404: no se revela que existe). Eventos ACCESS_DENIED.
```

**Privilegio mínimo (OPERADOR)**

```
OPERADOR: catálogo y pedidos 200; eventos de seguridad, configuración y carrito 403.
```

**OPERADOR: precios y estados**

```
Cambio de precio no altera órdenes anteriores (order_items conserva 4900 centavos). Precio negativo rechazado. Transiciones de estado válidas solamente.
```

**Inyección SQL / XSS / log injection**

```
Payloads de SQLi en login y en la URL -> 401/404 sin efecto (consultas parametrizadas). HTML en nombres escapado por la plantilla (autoescape). Saltos de línea en el correo no falsifican líneas de bitácora.
```

**Bitácora inmutable**

```
UPDATE y DELETE sobre security_events fallan por trigger: 'security_events es de solo escritura'.
```

**Eventos de seguridad (sección 16)**

```
Los 11 eventos exigidos están presentes (24 tipos en total); todos con usuario, evento, fecha/hora, resultado y origen.
```

**Subida de productos**

```
.exe, PNG falso y binario como .txt rechazados (400); ruta '../../libro.txt' saneada a 'libro.txt'. El archivo en disco (609f2b7504da….enc) no contiene el texto en claro; SHA-256 registrado.
```

**Integridad al descargar**

```
Se alteró 1 byte del producto cifrado: la descarga se rechaza (HTTP 500 genérico, sin detalles internos) y queda INTEGRITY_FAILURE.
```

**Fingerprint: unicidad, forja y robustez**

```
Cada comprador recibe bytes distintos del mismo producto. Una huella fabricada sin la clave HMAC se rechaza. Texto: sobrevive al recorte de la mitad del documento; se pierde si se eliminan los caracteres de ancho cero (limitación documentada).
```

**Fingerprint PNG (LSB)**

```
PSNR = 50.7 dB (>45 dB: imperceptible). Con 2 % de ruido en los LSB la huella se recupera por voto mayoritario. Tras recomprimir a JPEG se pierde (límite documentado).
```

**Respaldo alterado**

```
Al modificar un byte de un producto dentro del .zip: el hash de productos/0ce2af719421a626b8fdfd4a28dbaf4e.enc no coincide (archivo alterado). Sin --forzar no se sobrescribe la BD existente.
```

**Integración SSH/AAA con la BD de la tienda**

```
Autenticación contra la tabla users: {'ADMIN ssh:login / restart-service': (True, True), 'OPERADOR ssh:login / restart-service': (True, False), 'CLIENTE ssh:login': (False,)}. Contraseña errónea -> None. Registros en auditoria.log compartida. Usuarios de laboratorio originales intactos.
```

**Separación de responsabilidades**

```
Los conjuntos de permisos de CLIENTE, OPERADOR y ADMINISTRADOR solo comparten 'perfil:editar' y 'catalogo:ver'; el ADMINISTRADOR no gestiona productos ni compra, el OPERADOR no asigna roles; ningún rol tiene permisos sobre contraseñas ni claves.
```

**Pago con tarjeta (simulado)**

```
Rechazos con motivo visible: falta un dígito -> «El número de tarjeta está incompleto (falta 1 dígito).»; dígito verificador -> «El número de tarjeta no es válido (dígito verificador incorrecto).»; vencida -> «La tarjeta está vencida.»; CVV corto -> «El código de seguridad (CVV) debe tener 3 dígitos.»; sin apellido -> «El nombre del titular está incompleto (nombre y apellido como aparece en la tarjeta).»; banco declina -> «Tarjeta declinada por el banco emisor.». Con 4242 4242 4242 4242 el pago se aprueba. Ni el número, ni el titular, ni el CVV aparecen en la BD ni en los registros.
```

**Pago: sin atajos**

```
Enviar resultado=aprobar sin datos de tarjeta deja la orden PENDIENTE (pago rechazado).
```

**Verificación estricta de comprobantes**

```
Válido: original, re-formateado y con BOM. Inválido: total, nombre, precio de un producto, campo agregado, campo agregado dentro, key_id, algoritmo, firma, clave duplicada y orden alterada en la BD después de emitir el comprobante.
```

**Rastreo de copias (casos reales)**

```
Identificado: PDF renombrado a .txt, PNG sin extensión, Markdown con fin de línea Windows, Markdown guardado en UTF-16, Comprobante .json. El original sin huella, una huella de otra clave y un archivo ajeno se reportan con su causa.
```

**Catálogo ampliado**

```
20 productos en 6 categorías; filtro por categoría y búsqueda funcionan (y escapan la entrada); los 14 productos nuevos se descargan con huella recuperable.
```

