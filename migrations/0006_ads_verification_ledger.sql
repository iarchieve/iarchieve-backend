-- Independent advertising verification assessment ledger.
-- Assessments are evidence records, NOT final verification.
-- No billing, payment or settlement operations.

CREATE TABLE ads_verification_assessments (
    id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL,
    verifier_id TEXT NOT NULL
        CHECK(length(verifier_id) BETWEEN 1 AND 128),
    verdict TEXT NOT NULL
        CHECK(verdict IN ('accepted','rejected','inconclusive')),
    evidence_digest TEXT NOT NULL
        CHECK(length(evidence_digest)=64
          AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
    assessment_digest TEXT NOT NULL
        CHECK(length(assessment_digest)=64
          AND assessment_digest NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(claim_id)
        REFERENCES ads_impression_claims(id),
    UNIQUE(claim_id,verifier_id)
);

CREATE INDEX idx_ads_assessments_claim
ON ads_verification_assessments(claim_id,created_at);

CREATE INDEX idx_ads_assessments_verifier
ON ads_verification_assessments(verifier_id,created_at);

-- Preserve original assessments.
-- Corrections must be recorded through a future
-- explicitly designed supersession mechanism.

CREATE TRIGGER ads_assessments_no_update
BEFORE UPDATE ON ads_verification_assessments
BEGIN
    SELECT RAISE(ABORT,'assessment_immutable');
END;

CREATE TRIGGER ads_assessments_no_delete
BEFORE DELETE ON ads_verification_assessments
BEGIN
    SELECT RAISE(ABORT,'assessment_immutable');
END;