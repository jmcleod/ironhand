CREATE TABLE IF NOT EXISTS records (
    vault_id    TEXT   NOT NULL,
    record_type TEXT   NOT NULL,
    record_id   TEXT   NOT NULL,
    ver         INT    NOT NULL,
    scheme      TEXT   NOT NULL,
    nonce       BYTEA  NOT NULL,
    ciphertext  BYTEA  NOT NULL,
    version     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (vault_id, record_type, record_id)
);

CREATE INDEX IF NOT EXISTS idx_records_vault_type
    ON records (vault_id, record_type);

CREATE INDEX IF NOT EXISTS idx_records_vault_id
    ON records (vault_id);

CREATE TABLE IF NOT EXISTS epoch_cache (
    vault_id  TEXT   NOT NULL PRIMARY KEY,
    max_epoch BIGINT NOT NULL DEFAULT 0
);
