-- PoAE LOVE reservation lifecycle, version 1.
-- Additive migration: legacy session and assessment tables are preserved.
-- No TAS final adjudication or billing.

CREATE TABLE ads_love_evidence_reservations (
    id TEXT PRIMARY KEY,

    claim_id TEXT NOT NULL
        REFERENCES ads_impression_claims(id),

    verifier_id TEXT NOT NULL
        REFERENCES ads_verifier_registry(id),

    session_nonce TEXT NOT NULL UNIQUE
        CHECK(
            length(session_nonce)=32
            AND session_nonce NOT GLOB '*[^0-9a-f]*'
        ),

    status TEXT NOT NULL DEFAULT 'reserved'
        CHECK(status IN ('reserved','finalized','cancelled')),

    envelope_digest TEXT
        CHECK(
            envelope_digest IS NULL OR (
                length(envelope_digest)=64
                AND envelope_digest NOT GLOB '*[^0-9a-f]*'
            )
        ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    finalized_at TEXT,

    CHECK(
        (status='reserved'
            AND envelope_digest IS NULL
            AND finalized_at IS NULL)
        OR
        (status='cancelled'
            AND envelope_digest IS NULL
            AND finalized_at IS NULL)
        OR
        (status='finalized'
            AND envelope_digest IS NOT NULL
            AND finalized_at IS NOT NULL)
    )
);

-- At most one unfinalized reservation per claim/verifier.
-- Expired reservations must be explicitly cancelled.
CREATE UNIQUE INDEX idx_ads_love_active_reservation
ON ads_love_evidence_reservations(claim_id,verifier_id)
WHERE status='reserved';

CREATE INDEX idx_ads_love_reservation_expiry
ON ads_love_evidence_reservations(status,expires_at);

CREATE TRIGGER ads_love_reservation_insert_guard
BEFORE INSERT ON ads_love_evidence_reservations
BEGIN
    SELECT CASE WHEN
        NEW.status <> 'reserved'
        OR NEW.envelope_digest IS NOT NULL
        OR NEW.finalized_at IS NOT NULL
        OR NEW.expires_at <= CURRENT_TIMESTAMP
        OR NOT EXISTS (
            SELECT 1 FROM ads_impression_claims c
            WHERE c.id=NEW.claim_id
              AND c.verification_status='pending'
        )
        OR NOT EXISTS (
            SELECT 1 FROM ads_verifier_registry v
            WHERE v.id=NEW.verifier_id
              AND v.status='active'
        )
        OR EXISTS (
            SELECT 1 FROM ads_verification_assessments a
            WHERE a.claim_id=NEW.claim_id
              AND a.verifier_id=NEW.verifier_id
        )
        OR EXISTS (
            SELECT 1 FROM ads_love_verification_sessions s
            WHERE s.claim_id=NEW.claim_id
              AND s.verifier_id=NEW.verifier_id
              AND s.status='issued'
              AND s.expires_at>CURRENT_TIMESTAMP
        )
    THEN RAISE(ABORT,'love_reservation_forbidden')
    END;
END;

-- Existing reservation data is immutable.
-- Only reserved -> cancelled or reserved -> finalized is possible.
-- Finalization requires an actually inserted matching legacy session.

CREATE TRIGGER ads_love_reservation_update_guard
BEFORE UPDATE ON ads_love_evidence_reservations
BEGIN
    SELECT CASE WHEN
        OLD.status <> 'reserved'
        OR NEW.id IS NOT OLD.id
        OR NEW.claim_id IS NOT OLD.claim_id
        OR NEW.verifier_id IS NOT OLD.verifier_id
        OR NEW.session_nonce IS NOT OLD.session_nonce
        OR NEW.created_at IS NOT OLD.created_at
        OR NEW.expires_at IS NOT OLD.expires_at
        OR OLD.expires_at <= CURRENT_TIMESTAMP
        OR NEW.status NOT IN ('finalized','cancelled')
        OR (
            NEW.status='cancelled'
            AND (
                NEW.envelope_digest IS NOT NULL
                OR NEW.finalized_at IS NOT NULL
            )
        )
        OR (
            NEW.status='finalized'
            AND (
                NEW.finalized_at IS NOT CURRENT_TIMESTAMP
                OR NOT EXISTS (
                    SELECT 1 FROM ads_love_verification_sessions s
                    WHERE s.id=OLD.id
                      AND s.claim_id=OLD.claim_id
                      AND s.verifier_id=OLD.verifier_id
                      AND s.session_nonce=OLD.session_nonce
                      AND s.envelope_digest=NEW.envelope_digest
                      AND s.expires_at=OLD.expires_at
                      AND s.status='issued'
                )
            )
        )
    THEN RAISE(ABORT,'love_reservation_transition_forbidden')
    END;
END;

CREATE TRIGGER ads_love_reservation_delete_guard
BEFORE DELETE ON ads_love_evidence_reservations
BEGIN
    SELECT RAISE(ABORT,'love_reservation_immutable');
END;

-- Inserting the final session atomically finalizes its reservation.
-- An invalid/expired reservation causes the entire INSERT to roll back.

CREATE TRIGGER ads_love_finalize_on_session_insert
AFTER INSERT ON ads_love_verification_sessions
WHEN EXISTS (
    SELECT 1 FROM ads_love_evidence_reservations
    WHERE id=NEW.id
)
BEGIN
    UPDATE ads_love_evidence_reservations
    SET status='finalized',
        envelope_digest=NEW.envelope_digest,
        finalized_at=CURRENT_TIMESTAMP
    WHERE id=NEW.id
      AND claim_id=NEW.claim_id
      AND verifier_id=NEW.verifier_id
      AND session_nonce=NEW.session_nonce
      AND expires_at=NEW.expires_at
      AND status='reserved'
      AND expires_at>CURRENT_TIMESTAMP;

    SELECT CASE WHEN changes()<>1
    THEN RAISE(ABORT,'love_reservation_finalize_failed')
    END;
END;
-- All new LOVE sessions must be finalized from a matching reserved record.
-- Existing sessions remain intact; no legacy table rebuild.
CREATE TRIGGER ads_love_require_reservation
BEFORE INSERT ON ads_love_verification_sessions
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM ads_love_evidence_reservations r
    WHERE r.id=NEW.id
      AND r.claim_id=NEW.claim_id
      AND r.verifier_id=NEW.verifier_id
      AND r.session_nonce=NEW.session_nonce
      AND r.expires_at=NEW.expires_at
      AND r.status='reserved'
      AND r.expires_at>CURRENT_TIMESTAMP
  ) THEN RAISE(ABORT,'love_reservation_required') END;
END;
