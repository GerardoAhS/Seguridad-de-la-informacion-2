Infraestructura de Comunicaciones Seguras - Módulo de Administración y AAA

Aportación Individual
- Estudiante: Abril Márquez De La O 238488
- Responsabilidad: Módulo de administración remota segura mediante SSH, control de accesos (AAA: Autenticación, Autorización y Auditoría) y gestión de registros de eventos.

Descripción del Módulo
Esta sección implementa los mecanismos de control administrativo y trazabilidad, asegurando que las operaciones críticas dentro de la infraestructura estén reguladas y auditadas de forma permanente.

Componentes Principales:
1. Autenticación (aaa.py): Almacenamiento de credenciales utilizando hashes seguros con derivación de claves (scrypt/SHA-256) para evitar la exposición de contraseñas en texto plano.
2. Autorización basada en Roles (RBAC): Segmentación de privilegios según el perfil del usuario autenticado (administradores con acceso total y operadores con permisos limitados), bloqueando comandos o accesos no autorizados.
3. Administración Remota SSH (ssh_server.py / ssh_client.py): Simulación de consola administrativa remota sobre el puerto 2222, protegida mediante autenticación previa.
4. Sistema de Auditoría (auditoria.py / auditoria.log): Generación de bitácoras detalladas que registran eventos clave como conexiones exitosas, intentos de acceso fallidos, violación de privilegios y operaciones administrativas.

Instrucciones de Ejecución

1. Iniciar el Servidor SSH
En la máquina designada como servidor, ejecuta el servicio:
```bash
py ssh_server.py