-- Esquema de la base de datos de la tienda de contenido digital

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'CLIENTE'
                  CHECK (role IN ('CLIENTE', 'OPERADOR', 'ADMINISTRADOR')),
    status        TEXT NOT NULL DEFAULT 'ACTIVO'
                  CHECK (status IN ('ACTIVO', 'INACTIVO')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL NOT NULL CHECK (price >= 0),
    file_name   TEXT NOT NULL,
    file_hash   TEXT NOT NULL,          -- SHA-256 del archivo original
    status      TEXT NOT NULL DEFAULT 'ACTIVO'
                CHECK (status IN ('ACTIVO', 'INACTIVO')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    total      REAL NOT NULL,
    status     TEXT NOT NULL DEFAULT 'PENDIENTE',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS order_items (
    order_id   INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    price      REAL NOT NULL,           -- precio al momento de la compra
    PRIMARY KEY (order_id, product_id)
);

CREATE TABLE IF NOT EXISTS payments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id              INTEGER NOT NULL REFERENCES orders(id),
    transaction_reference TEXT NOT NULL,
    amount                REAL NOT NULL,
    status                TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    fingerprint TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT,                    -- puede ser un correo que no existe
    event      TEXT NOT NULL,
    result     TEXT NOT NULL,           -- OK / FALLO
    origin     TEXT,                    -- IP de origen
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
