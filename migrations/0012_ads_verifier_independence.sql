-- PR17: administrator assertions of controlling-party identities and conflicts.
-- This is NOT independent external verification or TAS adjudication.
CREATE TABLE ads_verifier_affiliations (
 verifier_id TEXT PRIMARY KEY REFERENCES ads_verifier_registry(id),
 controller_id TEXT NOT NULL CHECK(length(controller_id) BETWEEN 1 AND 128 AND controller_id NOT GLOB '*[^A-Za-z0-9_-]*'),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
 recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ads_verifier_affiliations_controller ON ads_verifier_affiliations(controller_id);
CREATE TABLE ads_verifier_controller_conflicts (
 controller_a TEXT NOT NULL CHECK(length(controller_a) BETWEEN 1 AND 128),
 controller_b TEXT NOT NULL CHECK(length(controller_b) BETWEEN 1 AND 128),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
 recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(controller_a,controller_b),
 CHECK(controller_a < controller_b)
);
CREATE TRIGGER ads_verifier_affiliations_immutable_update BEFORE UPDATE ON ads_verifier_affiliations BEGIN SELECT RAISE(ABORT,'affiliation_immutable'); END;
CREATE TRIGGER ads_verifier_affiliations_immutable_delete BEFORE DELETE ON ads_verifier_affiliations BEGIN SELECT RAISE(ABORT,'affiliation_immutable'); END;
CREATE TRIGGER ads_verifier_conflicts_immutable_update BEFORE UPDATE ON ads_verifier_controller_conflicts BEGIN SELECT RAISE(ABORT,'conflict_immutable'); END;
CREATE TRIGGER ads_verifier_conflicts_immutable_delete BEFORE DELETE ON ads_verifier_controller_conflicts BEGIN SELECT RAISE(ABORT,'conflict_immutable'); END;
