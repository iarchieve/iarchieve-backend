-- PoAE LOVE verification session ledger v1.
-- Non-billable, no final verification.
-- A session is bound to one claim and one registered verifier.

CREATE TABLE ads_love_verification_sessions (
    id TEXT PRIMARY KEY,

    claim_id TEXT NOT NULL,
    verifier_id TEXT NOT NULL,

    session_nonce TEXT NOT NULL UNIQUE
        CHECK(
            length(session_nonce)=32
            AND session_nonce NOT GLOB '*[^0-9a-f]*'
        ),

    envelope_digest TEXT NOT NULL
        CHECK(
            length(envelope_digest)=64
            AND envelope_digest NOT GLOB '*[^0-9a-f]*'
        ),

    status TEXT NOT NULL DEFAULT 'issued'
        CHECK(status IN ('issued','consumed','cancelled')),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,

    FOREIGN KEY(claim_id)
        REFERENCES ads_impression_claims(id),

    FOREIGN KEY(verifier_id)
        REFERENCES ads_verifier_registry(id),

    CHECK(
        (status='issued' AND consumed_at IS NULL)
        OR
        (status='cancelled' AND consumed_at IS NULL)
        OR
        (status='consumed' AND consumed_at IS NOT NULL)
    )
);

CREATE INDEX idx_ads_love_session_claim
ON ads_love_verification_sessions(claim_id,verifier_id);

CREATE INDEX idx_ads_love_session_status
ON ads_love_verification_sessions(status,expires_at);

-- New sessions must refer to pending claims and active verifiers.
-- The expiry must be later than the D1 server clock.

CREATE TRIGGER ads_love_session_insert_guard
BEFORE INSERT ON ads_love_verification_sessions
BEGIN
    SELECT CASE WHEN
        NEW.status <> 'issued'
        OR NEW.consumed_at IS NOT NULL
        OR NEW.expires_at <= CURRENT_TIMESTAMP
        OR NOT EXISTS (
            SELECT 1 FROM ads_impression_claims
            WHERE id=NEW.claim_id
              AND verification_status='pending'
        )
        OR NOT EXISTS (
            SELECT 1 FROM ads_verifier_registry
            WHERE id=NEW.verifier_id
              AND status='active'
        )
    THEN RAISE(ABORT,'love_session_issue_forbidden')
    END;
END;

-- The only allowed state changes are:
-- issued -> consumed (once, before expiry)
-- issued -> cancelled
-- All identity, binding and timing fields are immutable.

CREATE TRIGGER ads_love_session_update_guard
BEFORE UPDATE ON ads_love_verification_sessions
BEGIN
    SELECT CASE WHEN
        OLD.status <> 'issued'
        OR NEW.id <> OLD.id
        OR NEW.claim_id <> OLD.claim_id
        OR NEW.verifier_id <> OLD.verifier_id
        OR NEW.session_nonce <> OLD.session_nonce
        OR NEW.envelope_digest <> OLD.envelope_digest
        OR NEW.created_at <> OLD.created_at
        OR NEW.expires_at <> OLD.expires_at
        OR NEW.status NOT IN ('consumed','cancelled')
        OR (
            NEW.status='consumed'
            AND (
                OLD.expires_at <= CURRENT_TIMESTAMP
                OR NEW.consumed_at IS NULL
                OR NEW.consumed_at <> CURRENT_TIMESTAMP
                OR NOT EXISTS (
                    SELECT 1 FROM ads_verifier_registry
                    WHERE id=OLD.verifier_id
                      AND status='active'
                )
                OR NOT EXISTS (
                    SELECT 1 FROM ads_impression_claims
                    WHERE id=OLD.claim_id
                      AND verification_status='pending'
                )
            )
        )
        OR (
            NEW.status='cancelled'
            AND NEW.consumed_at IS NOT NULL
        )
    THEN RAISE(ABORT,'love_session_transition_forbidden')
    END;
END;

CREATE TRIGGER ads_love_session_delete_guard
BEFORE DELETE ON ads_love_verification_sessions
BEGIN
    SELECT RAISE(ABORT,'love_session_delete_forbidden');
END;