-- PoAE LOVE atomic assessment binding.
-- Legacy assessments remain non-final and nonbillable.
-- Session-bound assessments consume their session in the same statement.

ALTER TABLE ads_verification_assessments
ADD COLUMN love_session_id TEXT
REFERENCES ads_love_verification_sessions(id);

CREATE UNIQUE INDEX idx_ads_assessment_love_session
ON ads_verification_assessments(love_session_id)
WHERE love_session_id IS NOT NULL;

-- Session-bound assessment may only use an issued,
-- unexpired session belonging to the same claim and verifier.

CREATE TRIGGER ads_love_assessment_binding_guard
BEFORE INSERT ON ads_verification_assessments
WHEN NEW.love_session_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM ads_love_verification_sessions s
        JOIN ads_verifier_registry v
          ON v.id=s.verifier_id
        JOIN ads_impression_claims c
          ON c.id=s.claim_id
        WHERE s.id=NEW.love_session_id
          AND s.claim_id=NEW.claim_id
          AND s.verifier_id=NEW.verifier_id
          AND s.status='issued'
          AND s.expires_at>CURRENT_TIMESTAMP
          AND v.status='active'
          AND c.verification_status='pending'
    )
    THEN RAISE(ABORT,'love_assessment_binding_invalid')
    END;
END;

-- Atomic consumption is performed inside the same
-- INSERT statement. Trigger failure rolls back the assessment.

CREATE TRIGGER ads_love_assessment_consume_session
AFTER INSERT ON ads_verification_assessments
WHEN NEW.love_session_id IS NOT NULL
BEGIN
    UPDATE ads_love_verification_sessions
    SET status='consumed',
        consumed_at=CURRENT_TIMESTAMP
    WHERE id=NEW.love_session_id
      AND claim_id=NEW.claim_id
      AND verifier_id=NEW.verifier_id
      AND status='issued'
      AND expires_at>CURRENT_TIMESTAMP;

    SELECT CASE WHEN changes()<>1
    THEN RAISE(ABORT,'love_session_consume_failed')
    END;
END;