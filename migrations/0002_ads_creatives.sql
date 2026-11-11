CREATE TABLE IF NOT EXISTS ads_creatives (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  title TEXT NOT NULL,
  image_url TEXT NOT NULL,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(campaign_id) REFERENCES ads_campaigns(id)
);

CREATE INDEX IF NOT EXISTS idx_ads_creatives_campaign_status
ON ads_creatives(campaign_id,status);
