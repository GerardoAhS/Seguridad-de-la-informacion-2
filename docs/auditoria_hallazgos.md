# Auditoría de seguridad de la propia solución (sección 23, extra)

> **El equipo debe validar y adaptar estos hallazgos antes de entregarlos**: reproducir cada prueba y capturar pantalla de la evidencia.

## 1. Alcance
- **Sistema auditado:** aplicación web *Tienda Segura* (`aplicacion/`), base de datos SQLite (`base_de_datos/`), scripts de operación (`scripts/`) y módulo de infraestructura (`infraestructura/`: TLS/PKI, SSH, VPN/IPSec simuladas).
- **Incluye:** autenticación, autorización por roles, sesiones, manejo de claves, firma de comprobantes, fingerprinting, registro de eventos, respaldo y restauración.
- **Excluye:** el sistema operativo del servidor, la red física, pagos reales y servicios de terceros (no se probaron sistemas externos, conforme a la sección 21).
- **Ambiente:** instalación local de laboratorio con los datos de prueba de `scripts/inicializar.py`.

## 2. Criterios de auditoría
| Id | Criterio | Fuente |
|---|---|---|
| C1 | Contraseñas solo como hash Argon2id/bcrypt; autenticación robusta frente a abuso | Documento del proyecto §7; OWASP ASVS V2 |
| C2 | La clave privada de firma en archivo/configuración externa con permisos restringidos | Documento del proyecto §11.1 |
| C3 | Administración por SSH con usuario no-root y, de preferencia, par de claves | Documento del proyecto §14 |
| C4 | Fingerprint que forme parte del contenido y sea recuperable (robustez justificada) | Documento del proyecto §12 |
| C5 | Respaldo y restauración de la información crítica, protegiendo su confidencialidad | Documento del proyecto §17; ISO/IEC 27002 8.13 |
| C6 | Registro de eventos íntegro y no modificable | Documento del proyecto §16; ISO/IEC 27002 8.15 |

## 3. Controles seleccionados y evidencia revisada
| Control | Evidencia | Prueba ejecutada |
|---|---|---|
| Hash de contraseñas y bloqueo por intentos | `aplicacion/seguridad.py`, tabla `users` | `test_01_contrasena_incorrecta_acceso_rechazado`, `test_bloqueo_por_intentos_fallidos` |
| Gestión de la clave de firma | `claves_privadas/`, `aplicacion/cripto.py` (`FIRMA_PASSPHRASE`) | Revisión de permisos y configuración |
| Acceso SSH | `infraestructura/ssh_server.py`, `aplicacion/puente_aaa.py` | `test_ssh_usa_los_usuarios_de_la_tienda_con_privilegio_minimo` |
| Fingerprint | `aplicacion/fingerprint.py` | `test_fingerprint_es_distinto_por_comprador…`, `test_rastreo_de_copias_en_casos_reales` |
| Respaldo | `aplicacion/respaldo.py` | `test_13_restauracion_de_respaldo_recupera_informacion`, `test_respaldo_alterado_no_se_restaura` |
| Bitácora | tabla `security_events`, `registros/auditoria.log` | `test_bitacora_de_eventos_es_de_solo_escritura` |

Resultado de las pruebas: ver `evidencias/resultados_pruebas.md` (43/43 aprobadas).

## 4. Hallazgos

### Hallazgo 1 · El bloqueo por cuenta permite bloquear a una víctima
- **Criterio:** C1. La autenticación debe resistir abuso sin afectar la disponibilidad para el usuario legítimo.
- **Condición:** tras 5 intentos fallidos con un correo, esa cuenta queda bloqueada 15 minutos, aunque quien falla no sea el dueño.
- **Causa:** el contador de intentos se lleva solo por cuenta, no por origen (IP) ni con retardo progresivo.
- **Riesgo:** **Medio.** Denegación de servicio dirigida: un tercero que conozca el correo puede impedir que el cliente entre.
- **Evidencia:** `test_bloqueo_por_intentos_fallidos` (la 6.ª solicitud recibe 429); eventos `LOGIN_FAILED` en *Eventos*.
- **Recomendación:** limitar también por IP, retardo progresivo o CAPTCHA, avisar por correo al dueño y permitir desbloqueo con enlace.

### Hallazgo 2 · La clave privada de firma está en disco sin passphrase por defecto
- **Criterio:** C2. La clave privada debe protegerse con permisos restringidos; el rol administrativo no implica acceso a todos los secretos.
- **Condición:** `claves_privadas/firma_privada.pem` tiene permisos 0600, pero `FIRMA_PASSPHRASE` es opcional y por defecto la clave no está cifrada.
- **Causa:** se priorizó que la instalación de laboratorio funcione con tres comandos.
- **Riesgo:** **Alto.** Quien lea el archivo (p. ej. con acceso al usuario del servidor) puede emitir comprobantes falsos que verificarían como válidos, anulando el no repudio.
- **Evidencia:** `ls -l claves_privadas/`; `aplicacion/cripto.py` solo cifra la clave si existe la variable `FIRMA_PASSPHRASE`.
- **Recomendación:** passphrase obligatoria fuera del modo laboratorio, o mover la firma a un HSM/KMS o a un servicio separado; rotación periódica de la clave.

### Hallazgo 3 · El acceso SSH usa contraseña, no par de claves
- **Criterio:** C3. Se recomienda autenticación SSH por par de claves.
- **Condición:** `infraestructura/ssh_server.py` solo implementa autenticación `password` contra la tabla `users`.
- **Causa:** se reutilizaron las identidades de la tienda para tener una sola fuente de usuarios; la autenticación por clave pública no se implementó en el servidor simulado.
- **Riesgo:** **Medio.** Expuesto a fuerza bruta o reutilización de contraseñas, mitigado por el registro AAA y porque el diseño restringe SSH a la VPN.
- **Evidencia:** `check_auth_password` en `ssh_server.py`; `auditoria.log` con intentos SSH.
- **Recomendación:** en el despliegue real, `sshd_config` con `PasswordAuthentication no`, `PermitRootLogin no`, `AllowUsers` del grupo de administración y acceso solo desde la red VPN (ver `docs/arquitectura_seguridad.md` §6).

### Hallazgo 4 · El fingerprint de texto se elimina al normalizar Unicode
- **Criterio:** C4. La técnica debe justificarse en robustez.
- **Condición:** en archivos `.txt`/`.md` la huella va en caracteres de ancho cero; si se copia el texto a un editor que los elimina o se normaliza, la huella desaparece.
- **Causa:** se eligió una técnica imperceptible y de buena capacidad, pero de baja robustez ante transformaciones del texto.
- **Riesgo:** **Medio.** Una copia filtrada "limpiada" ya no permite identificar al comprador.
- **Evidencia:** `test_fingerprint_es_distinto_por_comprador…` (el texto limpiado no devuelve huella); *Rastrear copia* explica la causa.
- **Recomendación:** combinar técnicas (variaciones léxicas/espaciado, marca visible en el encabezado), y para PDF/PNG mantener las técnicas actuales, que sí resisten ruido leve.

### Hallazgo 5 · Los respaldos no van cifrados
- **Criterio:** C5. El respaldo debe proteger la confidencialidad de la información crítica.
- **Condición:** el `.zip` de `respaldos/` contiene la base de datos en claro (correos, órdenes); el manifiesto está firmado (integridad), pero el contenido no está cifrado.
- **Causa:** la protección se enfocó en integridad y en no incluir las claves privadas.
- **Riesgo:** **Medio.** Una copia de respaldo extraviada expone datos personales de los usuarios.
- **Evidencia:** `aplicacion/respaldo.py`; abrir cualquier respaldo con un descompresor.
- **Recomendación:** cifrar el respaldo con una clave aparte (AES-GCM), guardar copia fuera del sitio (regla 3-2-1) y probar la restauración periódicamente.

### Otros hallazgos menores
| # | Hallazgo | Riesgo | Recomendación |
|---|---|---|---|
| 6 | `auditoria.log` en texto plano sin encadenado de hashes (la tabla `security_events` sí es inmutable por triggers) | Bajo-Medio | Enviar a syslog/SIEM y encadenar hashes |
| 7 | Sin `argon2-cffi` el sistema usa scrypt (válido, pero distinto al recomendado) | Bajo | Fallar al iniciar en producción si no está Argon2id |
| 8 | PKI de laboratorio sin CRL/OCSP; VPN e IPSec simuladas | Bajo | Documentado como límite; usar WireGuard/strongSwan en un despliegue real |

## 5. Conclusión
Los controles exigidos funcionan y están probados. Los hallazgos de mayor prioridad son la protección de la clave de firma (H2) y la autenticación SSH por clave pública (H3), seguidos por el cifrado de respaldos (H5).
