-- Add format to existing placement records.
-- Existing placements remain display inventory.

ALTER TABLE ads_placements
ADD COLUMN format TEXT NOT NULL DEFAULT 'display'
CHECK(format IN ('display','video','native'));

CREATE INDEX IF NOT EXISTS idx_ads_placements_status_format
ON ads_placements(status,format);