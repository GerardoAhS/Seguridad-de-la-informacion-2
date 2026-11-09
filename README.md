# Plataforma segura de venta y distribución de contenido digital

Proyecto final de Seguridad. Tienda web de productos digitales con pagos simulados.

## Estado del avance

| Parte | Estado |
|---|---|
| Estructura del repositorio | Hecho |
| Base de datos (7 tablas + datos de prueba) | Hecho |
| Registro e inicio de sesión (hash Argon2id) | Hecho |
| Catálogo y detalle de producto | Hecho |
| Registro de eventos de login/logout | Hecho |
| Carrito, órdenes y pago simulado | Pendiente |
| Comprobante con firma digital | Pendiente |
| Fingerprinting en descargas | Pendiente |
| Paneles por rol (cliente, operador, administrador) | Pendiente |
| CA local y HTTPS | Pendiente |
| Respaldo y restauración | Pendiente |
| Pruebas obligatorias y auditoría | Pendiente |

## Instalación

Requiere Python 3.9 o superior.

```
pip install -r requirements.txt
python base_de_datos/crear_bd.py
python aplicacion/app.py
```

Abrir http://localhost:5000

## Usuarios de prueba

| Correo | Contraseña | Rol |
|---|---|---|
| cliente@tienda.com | Cliente123! | CLIENTE |
| operador@tienda.com | Operador123! | OPERADOR |
| admin@tienda.com | Admin123! | ADMINISTRADOR |

Los registros nuevos siempre entran como CLIENTE.

## Estructura

```
aplicacion/        código de la app (Flask)
base_de_datos/     esquema.sql y crear_bd.py
certificados/      certificados (las claves privadas NO se suben)
claves_publicas/   claves públicas para verificar firmas
scripts/           scripts de apoyo (respaldo, etc.)
productos/         archivos digitales de prueba
respaldos/         respaldos generados
evidencias/        capturas y resultados de las pruebas
```

## Notas de seguridad

- Las contraseñas se guardan con Argon2id; no existe columna con la contraseña original.
- El mensaje de error del login es el mismo si el correo no existe o la contraseña es incorrecta.
- Las claves privadas están en `.gitignore`.
