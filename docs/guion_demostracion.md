# Guion de demostración (≈ 10 min)

Preparación: `python scripts/inicializar.py --reset` y `python scripts/ejecutar_servidor.py`; importar `certificados/ca.crt` en el navegador.

1. **TLS** — abrir https://localhost:5443 (candado válido). Mostrar `curl https://localhost:5443` sin la CA → error 60 (el cliente rechaza). `python scripts/correr_pruebas.py` ya prueba CA falsa, caducado y otro nombre.
2. **Autenticación** — login de `ana@tienda.test` con contraseña mala (rechazo) y buena. Mostrar en `/admin/eventos` (como admin) el `LOGIN_FAILED`.
3. **Autorización** — como ana abrir `/admin/usuarios` → 403. Como operador intentar asignar un rol → 403. Como admin asignar rol → permitido.
4. **Compra** — ana agrega 2 productos, crea la orden, paga (simulado aprobado).
5. **Firma digital** — abrir el comprobante ("FIRMA VÁLIDA"), descargar el `.json`, editar el total, subirlo en *Verificar firma* → "Firma inválida". También `python scripts/verificar_comprobante.py comprobante_orden_1.json`.
6. **Hash/integridad** — `python scripts/verificar_hash.py` sobre un archivo; alterar un byte y repetir.
7. **Fingerprint** — ana descarga el PDF/PNG; como admin subir esa copia en *Fingerprint* → identifica a ana, la orden y la hora. Mostrar que cambiar el nombre del archivo no importa.
8. **Producto no comprado** — ana abre `/descargas/<orden>/2` de un producto que no compró → 403 y `DOWNLOAD/DENEGADO` en eventos.
9. **Respaldo** — `python scripts/respaldar.py`, borrar `base_de_datos/tienda.db`, `python scripts/restaurar.py <zip>`; la app vuelve con todo.
10. **SSH** (opcional) — `python scripts/iniciar_ssh.py` y `python infraestructura/ssh_client.py`: admin ejecuta `restart-service`; operador solo `status` (rechazo registrado).
