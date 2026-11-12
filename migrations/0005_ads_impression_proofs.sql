-- Advertising delivery and impression evidence foundation.
-- This migration creates no billable events.
-- No personal or device identifiers are stored.

CREATE TABLE IF NOT EXISTS ads_delivery_requests (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    creative_id TEXT NOT NULL,
    placement_id TEXT NOT NULL,
    issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued'
        CHECK(status IN ('issued','expired','cancelled')),
    FOREIGN KEY(campaign_id) REFERENCES ads_campaigns(id),
    FOREIGN KEY(creative_id) REFERENCES ads_creatives(id),
    FOREIGN KEY(placement_id) REFERENCES ads_placements(id)
);

CREATE TABLE IF NOT EXISTS ads_impression_claims (
    id TEXT PRIMARY KEY,
    delivery_request_id TEXT NOT NULL UNIQUE,
    proof_digest TEXT NOT NULL
        CHECK(length(proof_digest) = 64),
    verification_status TEXT NOT NULL DEFAULT 'pending'
        CHECK(verification_status IN (
            'pending','verified','rejected'
        )),
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TEXT,
    FOREIGN KEY(delivery_request_id)
        REFERENCES ads_delivery_requests(id)
);

CREATE INDEX IF NOT EXISTS idx_ads_delivery_placement
ON ads_delivery_requests(placement_id,issued_at);

CREATE INDEX IF NOT EXISTS idx_ads_delivery_campaign
ON ads_delivery_requests(campaign_id,issued_at);

CREATE INDEX IF NOT EXISTS idx_ads_claims_verification
ON ads_impression_claims(verification_status,received_at);