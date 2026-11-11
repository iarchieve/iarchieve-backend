CREATE TABLE IF NOT EXISTS ads_publisher_credentials (
    id TEXT PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE
        CHECK(length(token_hash) = 64),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','revoked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    FOREIGN KEY(publisher_id) REFERENCES ads_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_ads_publisher_credentials_owner
ON ads_publisher_credentials(publisher_id,status);