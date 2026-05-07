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
    token       TEXT        NOT NULL DEFAULT '',  -- HMAC token, opaque to customer
    used        BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_id_idx    ON sessions (id);
CREATE INDEX IF NOT EXISTS sessions_uid_idx   ON sessions (uid);
CREATE INDEX IF NOT EXISTS sessions_token_idx ON sessions (token);  -- fast token lookup

-- If sessions table already exists, just add the token column:
-- ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token TEXT NOT NULL DEFAULT '';
-- CREATE INDEX IF NOT EXISTS sessions_token_idx ON sessions (token);

-- Verify
SELECT 'nfc_tags' AS table_name, COUNT(*) AS rows FROM nfc_tags
UNION ALL
SELECT 'sessions', COUNT(*) FROM sessions;