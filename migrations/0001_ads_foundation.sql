PRAGMA foreign_keys = ON;

-- 광고 플랫폼 계정
CREATE TABLE IF NOT EXISTS ads_accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK(role IN ('advertiser','publisher','admin')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','active','suspended')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 광고 캠페인
CREATE TABLE IF NOT EXISTS ads_campaigns (
    id TEXT PRIMARY KEY,
    advertiser_id TEXT NOT NULL,
    name TEXT NOT NULL,
    format TEXT NOT NULL
        CHECK(format IN ('display','video','native')),
    daily_budget_krw INTEGER NOT NULL
        CHECK(daily_budget_krw > 0),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft','paused','active','archived')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(advertiser_id) REFERENCES ads_accounts(id)
);

-- 광고 매체 및 지면
CREATE TABLE IF NOT EXISTS ads_placements (
    id TEXT PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    name TEXT NOT NULL,
    floor_cpm_krw INTEGER NOT NULL
        CHECK(floor_cpm_krw >= 0),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','approved','rejected','paused')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(publisher_id) REFERENCES ads_accounts(id)
);

-- 광고 거래 및 검증을 위한 이벤트 원장
CREATE TABLE IF NOT EXISTS ads_events (
    id TEXT PRIMARY KEY,
    campaign_id TEXT,
    placement_id TEXT,
    event_type TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'unverified'
        CHECK(verification_status IN
            ('unverified','pending','verified','rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(campaign_id) REFERENCES ads_campaigns(id),
    FOREIGN KEY(placement_id) REFERENCES ads_placements(id)
);

-- 운영 변경 이력
CREATE TABLE IF NOT EXISTS ads_audit_log (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ads_campaigns_advertiser
    ON ads_campaigns(advertiser_id);

CREATE INDEX IF NOT EXISTS idx_ads_placements_publisher
    ON ads_placements(publisher_id);

CREATE INDEX IF NOT EXISTS idx_ads_events_campaign
    ON ads_events(campaign_id);

CREATE INDEX IF NOT EXISTS idx_ads_audit_actor
    ON ads_audit_log(actor_id);
