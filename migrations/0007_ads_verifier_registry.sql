-- Independent verifier public key registry.
-- Enrollment is restricted to a future administrator procedure.
-- No public self-registration and no private keys are stored.

CREATE TABLE ads_verifier_registry (
    id TEXT PRIMARY KEY
        CHECK(length(id) BETWEEN 1 AND 128),
    public_key_jwk TEXT NOT NULL
        CHECK(json_valid(public_key_jwk)),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','revoked')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ads_verifier_registry_status
ON ads_verifier_registry(status);

-- No in-place key replacement.
-- New identities / key versions require separate registration.

CREATE TRIGGER ads_verifier_registry_no_delete
BEFORE DELETE ON ads_verifier_registry
BEGIN
    SELECT RAISE(ABORT,'verifier_registry_immutable');
END;

CREATE TRIGGER ads_verifier_registry_no_key_change
BEFORE UPDATE OF id,public_key_jwk ON ads_verifier_registry
BEGIN
    SELECT RAISE(ABORT,'verifier_key_immutable');
END;