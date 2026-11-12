-- PR18 TAS bridge: immutable, non-billable handoff requests only.
-- TAS engine and final adjudication are NOT implemented by this migration.
CREATE TABLE ads_tas_handoff_requests (
  id TEXT PRIMARY KEY,
  claim_id TEXT NOT NULL UNIQUE REFERENCES ads_impression_claims(id),
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
  payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
  state TEXT NOT NULL DEFAULT 'awaiting_tas' CHECK(state='awaiting_tas'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_ads_tas_handoff_created ON ads_tas_handoff_requests(created_at);
CREATE TRIGGER ads_tas_handoff_no_update BEFORE UPDATE ON ads_tas_handoff_requests
BEGIN SELECT RAISE(ABORT,'tas_handoff_immutable'); END;
CREATE TRIGGER ads_tas_handoff_no_delete BEFORE DELETE ON ads_tas_handoff_requests
BEGIN SELECT RAISE(ABORT,'tas_handoff_immutable'); END;
