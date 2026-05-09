-- ============================================================
-- PostgreSQL Schema — NFC Beach Bar Ordering System
-- ============================================================

CREATE TABLE IF NOT EXISTS nfc_tags (
    uid           TEXT    PRIMARY KEY,
    table_id      TEXT    NOT NULL,
    last_counter  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    uid         TEXT        NOT NULL,
    table_id    TEXT        NOT NULL,
    counter     INTEGER     NOT NULL,
    token       TEXT        NOT NULL DEFAULT '',
    used        BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_id_idx    ON sessions (id);
CREATE INDEX IF NOT EXISTS sessions_uid_idx   ON sessions (uid);
CREATE INDEX IF NOT EXISTS sessions_token_idx ON sessions (token);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  UUID        NOT NULL,
    table_id    TEXT        NOT NULL,
    items       JSONB       NOT NULL DEFAULT '[]',
    status      TEXT        NOT NULL DEFAULT 'pending',  -- pending, preparing, ready, delivered
    total       NUMERIC     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS orders_table_idx   ON orders (table_id);
CREATE INDEX IF NOT EXISTS orders_status_idx  ON orders (status);
CREATE INDEX IF NOT EXISTS orders_created_idx ON orders (created_at DESC);

-- Admin users table
CREATE TABLE IF NOT EXISTS admin_users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Test admin user: username=admin password=admin123
-- Password is bcrypt hash of 'admin123'
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQyCCKSMhCGqhfNR8q.7Zq0Oi')
ON CONFLICT (username) DO NOTHING;

-- Verify
SELECT 'nfc_tags'    AS table_name, COUNT(*) AS rows FROM nfc_tags    UNION ALL
SELECT 'sessions',                  COUNT(*)          FROM sessions    UNION ALL
SELECT 'orders',                    COUNT(*)          FROM orders      UNION ALL
SELECT 'admin_users',               COUNT(*)          FROM admin_users;