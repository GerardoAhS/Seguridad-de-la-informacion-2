# Matriz de cumplimiento frente al documento del proyecto

Estado: ✅ implementado y probado · 🟡 implementado con límite documentado · ⬜ pendiente del equipo

| Requisito del documento | Estado | Dónde |
|---|---|---|
| Registro, login, logout, perfil, recuperación de contraseña | ✅ | `rutas_publicas.py` |
| Catálogo, carrito, órdenes, pago simulado | ✅ | `rutas_publicas.py`, `rutas_cliente.py` |
| Descarga de productos comprados | ✅ | `rutas_cliente.descargar` |
| Roles CLIENTE / OPERADOR / ADMINISTRADOR y privilegio mínimo (sección 5) | ✅ | `seguridad.PERMISOS` |
| Base de datos relacional (7 tablas + auxiliares), script y datos de prueba | ✅ | `base_de_datos/schema.sql`, `datos_demo.py` |
| Contraseñas con Argon2id/bcrypt; nunca en claro | ✅ (Argon2id; scrypt como alternativa) | `seguridad.py` |
| Sesiones seguras, expiración, revocación, CSRF | ✅ | `seguridad.py` |
| Validación de entradas, SQLi, XSS, errores seguros | ✅ | pruebas adicionales |
| HTTPS / TLS con CA local | ✅ | `scripts/ejecutar_servidor.py` |
| Firma digital de comprobantes + verificación | ✅ | `servicios.py`, `scripts/verificar_comprobante.py` |
| Hash SHA-256 de archivos | ✅ (usar el módulo del equipo si lo prefieren) | `cripto.py` |
| Fingerprinting (≥ 1 tipo de archivo, con extracción) | ✅ txt/md, pdf, png | `fingerprint.py` |
| Eventos de seguridad (sección 16) | ✅ 11 exigidos + extras | `eventos.py` |
| Respaldo y restauración demostrada | ✅ | `respaldo.py`, prueba 13 |
| 13 pruebas mínimas con evidencia | ✅ | `evidencias/resultados_pruebas.md` |
| SSH / VPN / IPSec | 🟡 simulados; SSH integrado a la BD | `infraestructura/`, `puente_aaa.py` |
| Auditoría con alcance, criterios, controles y ≥ 3 hallazgos (criterio, condición, causa, riesgo, evidencia, recomendación) | 🟡 completa; falta que el equipo la valide con capturas | `docs/auditoria_hallazgos.md` |
| Repositorio sin secretos | ✅ `.gitignore` | — |
| Capturas de pantalla de la app en uso | ⬜ | tomarlas siguiendo `docs/guion_demostracion.md` |
| Documento final (portada, integrantes, conclusiones) | ⬜ | usar `docs/arquitectura_seguridad.md` como base |
| Presentación y demostración final | ⬜ | guion en `docs/guion_demostracion.md` |
| Prueba de SSH real con paramiko y las 31 pruebas originales | ⬜ | no se pudieron ejecutar en el entorno de construcción (sin paramiko/pytest); correr `cd infraestructura && python -m pytest` |
