-- PoAE verifier governance: additive, non-billable, no key replacement.
-- Existing verifier rows remain unchanged.
CREATE UNIQUE INDEX idx_ads_verifier_unique_p256_key
ON ads_verifier_registry(
  json_extract(public_key_jwk,'$.x'),
  json_extract(public_key_jwk,'$.y')
)
WHERE json_extract(public_key_jwk,'$.kty')='EC'
  AND json_extract(public_key_jwk,'$.crv')='P-256'
  AND length(json_extract(public_key_jwk,'$.x'))=43
  AND length(json_extract(public_key_jwk,'$.y'))=43;

-- Revocation is permanent; identity and key are already immutable in 0007.
CREATE TRIGGER ads_verifier_no_reactivation
BEFORE UPDATE OF status ON ads_verifier_registry
WHEN OLD.status<>'active' OR NEW.status<>'revoked'
BEGIN
  SELECT RAISE(ABORT,'verifier_status_transition_forbidden');
END;

-- Append-only activity record generated inside the same SQL statement.
-- The ledger records database events, not authenticated human identities.
CREATE TABLE ads_verifier_registry_events (
  id TEXT PRIMARY KEY,
  verifier_id TEXT NOT NULL REFERENCES ads_verifier_registry(id),
  event_type TEXT NOT NULL CHECK(event_type IN ('registered','revoked')),
  recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ads_verifier_registry_events_verifier
  ON ads_verifier_registry_events(verifier_id,recorded_at);

CREATE TRIGGER ads_verifier_event_insert
AFTER INSERT ON ads_verifier_registry
BEGIN
  INSERT INTO ads_verifier_registry_events(id,verifier_id,event_type)
  VALUES (lower(hex(randomblob(16))),NEW.id,'registered');
END;
CREATE TRIGGER ads_verifier_event_revoke
AFTER UPDATE OF status ON ads_verifier_registry
WHEN OLD.status='active' AND NEW.status='revoked'
BEGIN
  INSERT INTO ads_verifier_registry_events(id,verifier_id,event_type)
  VALUES (lower(hex(randomblob(16))),NEW.id,'revoked');
END;
CREATE TRIGGER ads_verifier_events_no_update
BEFORE UPDATE ON ads_verifier_registry_events
BEGIN SELECT RAISE(ABORT,'verifier_event_immutable'); END;
CREATE TRIGGER ads_verifier_events_no_delete
BEFORE DELETE ON ads_verifier_registry_events
BEGIN SELECT RAISE(ABORT,'verifier_event_immutable'); END;
