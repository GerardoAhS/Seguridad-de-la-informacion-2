-- Esquema relacional (SQLite). Para PostgreSQL/MySQL basta cambiar AUTOINCREMENT y los tipos de fecha.
-- Los importes se guardan en CENTAVOS (enteros) para evitar errores de redondeo de los flotantes:
-- products.price_cents / order_items.price_cents / orders.total_cents / payments.amount_cents.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,                 -- Argon2id (o scrypt si no está argon2-cffi). NUNCA la contraseña original.
    name          TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('CLIENTE','OPERADOR','ADMINISTRADOR')),
    status        TEXT NOT NULL DEFAULT 'ACTIVO' CHECK (status IN ('ACTIVO','DESACTIVADO')),
    created_at    TEXT NOT NULL,
    last_login    TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0      -- 1 cuando el usuario confirmó su correo con el código enviado
);

CREATE TABLE IF NOT EXISTS products (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL,
    price_cents   INTEGER NOT NULL CHECK (price_cents >= 0),
    file_name     TEXT NOT NULL UNIQUE,          -- nombre interno del archivo CIFRADO en productos/
    download_name TEXT NOT NULL,                 -- nombre con el que lo recibe el comprador
    file_type     TEXT NOT NULL CHECK (file_type IN ('txt','md','pdf','png')),
    file_hash     TEXT NOT NULL,                 -- SHA-256 del archivo ORIGINAL (verificación de integridad)
    status        TEXT NOT NULL DEFAULT 'ACTIVO' CHECK (status IN ('ACTIVO','INACTIVO')),
    created_at    TEXT NOT NULL,
    category      TEXT NOT NULL DEFAULT 'Material educativo',   -- Libros electrónicos, Manuales, Documentos técnicos...
    highlights    TEXT NOT NULL DEFAULT ''                       -- "qué incluye", una línea por punto
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
    status      TEXT NOT NULL DEFAULT 'PENDIENTE' CHECK (status IN ('PENDIENTE','PAGADA','COMPLETADA','CANCELADA')),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),   -- precio al momento de la compra
    PRIMARY KEY (order_id, product_id)
);

CREATE TABLE IF NOT EXISTS payments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id              INTEGER NOT NULL REFERENCES orders(id),
    transaction_reference TEXT NOT NULL UNIQUE,
    amount_cents          INTEGER NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('APROBADO','RECHAZADO')),
    created_at            TEXT NOT NULL,
    detail                TEXT NOT NULL DEFAULT ''   -- motivo del rechazo. NUNCA datos de la tarjeta (no se guardan)
);

CREATE TABLE IF NOT EXISTS receipts (          -- comprobante firmado digitalmente
    order_id   INTEGER PRIMARY KEY REFERENCES orders(id),
    content    TEXT NOT NULL,                  -- JSON canónico que se firmó
    signature  TEXT NOT NULL,                  -- RSA-PSS / SHA-256, en base64
    key_id     TEXT NOT NULL,                  -- huella de la clave pública que verifica
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS downloads (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    order_id         INTEGER NOT NULL REFERENCES orders(id),
    product_id       INTEGER NOT NULL REFERENCES products(id),
    fingerprint      TEXT NOT NULL,            -- carga útil insertada en la copia (hex)
    delivered_sha256 TEXT NOT NULL,            -- hash de la copia personalizada entregada
    ip               TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    user_email TEXT,                           -- usuario (o el correo que se intentó usar)
    event      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    result     TEXT NOT NULL,
    origin     TEXT,                           -- IP de origen
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_email_time ON security_events(user_email, event, created_at);

-- La bitácora es de solo-agregar: ni siquiera la aplicación puede modificar o borrar eventos.
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON security_events
BEGIN SELECT RAISE(ABORT, 'security_events es de solo escritura'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON security_events
BEGIN SELECT RAISE(ABORT, 'security_events es de solo escritura'); END;

CREATE TABLE IF NOT EXISTS sessions (          -- sesiones del lado del servidor (permiten revocarlas)
    id_hash    TEXT PRIMARY KEY,               -- SHA-256 del token de la cookie (el token nunca se guarda)
    user_id    INTEGER REFERENCES users(id),   -- NULL = sesión anónima
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    ip         TEXT,
    flash      TEXT NOT NULL DEFAULT '[]'      -- avisos pendientes de mostrar (JSON)
);

CREATE TABLE IF NOT EXISTS cart_items (
    user_id    INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    PRIMARY KEY (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,               -- SHA-256 del token del enlace enviado al usuario
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    code_hash  TEXT NOT NULL DEFAULT '',       -- SHA-256 del código de 6 dígitos enviado en el mismo correo
    attempts   INTEGER NOT NULL DEFAULT 0      -- intentos fallidos con el código (se invalida al llegar al límite)
);

CREATE TABLE IF NOT EXISTS email_verifications (   -- códigos para confirmar el correo al registrarse
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
