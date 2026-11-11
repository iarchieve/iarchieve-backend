import test from "node:test";
import assert from "node:assert/strict";

const base = process.env.ADS_TEST_BASE;
const token = (letter) => `Bearer ${letter.repeat(64)}`;

async function api(method, path, role, body) {
  const headers = {
    Authorization: token(role)
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  return {
    status: response.status,
    data: await response.json()
  };
}

test("PR7 real local D1 lifecycle", { skip: !base && "Requires ADS_TEST_BASE" }, async (t) => {
  assert.match(base || "", /^http:\/\/127\.0\.0\.1:\d+$/);

  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);

  const nonce = crypto.randomUUID().slice(0, 8);

  const placement = await api("POST", "/api/ads/placements", "C", {
    publisher_id: "pub-test-001",
    name: `PR7 placement ${nonce}`,
    floor_cpm_krw: 1000
  });
  assert.equal(placement.status, 201);
  assert.equal(placement.data.status, "pending");

  const placementId = placement.data.id;

  const blockedPlacement = await api(
    "GET",
    `/api/ads/delivery/next?placement_id=${placementId}`,
    "C"
  );
  assert.equal(blockedPlacement.status, 409);

  const approvedPlacement = await api(
    "PATCH",
    `/api/ads/placements/${placementId}`,
    "A",
    { status: "approved" }
  );
  assert.equal(approvedPlacement.status, 200);

  const campaign = await api("POST", "/api/ads/campaigns", "B", {
    advertiser_id: "adv-test-001",
    name: `PR7 campaign ${nonce}`,
    format: "display",
    daily_budget_krw: 50000
  });
  assert.equal(campaign.status, 201);
  assert.equal(campaign.data.status, "draft");

  const campaignId = campaign.data.id;

  const creative = await api("POST", "/api/ads/creatives", "B", {
    campaign_id: campaignId,
    title: `PR7 creative ${nonce}`,
    image_url: "https://example.com/pr7-test.png",
    target_url: "https://example.com/pr7"
  });
  assert.equal(creative.status, 201);
  assert.equal(creative.data.status, "pending");

  const creativeId = creative.data.id;

  const forbidden = await api(
    "PATCH",
    `/api/ads/creatives/${creativeId}`,
    "B",
    { status: "approved" }
  );
  assert.equal(forbidden.status, 403);

  const beforeApproval = await api(
    "GET",
    `/api/ads/delivery/next?placement_id=${placementId}`,
    "C"
  );
  assert.equal(beforeApproval.status, 200);
  assert.notEqual(beforeApproval.data.item?.creative_id, creativeId);

  const activate = await api(
    "PATCH",
    `/api/ads/campaigns/${campaignId}`,
    "B",
    { status: "active" }
  );
  assert.equal(activate.status, 200);

  const approve = await api(
    "PATCH",
    `/api/ads/creatives/${creativeId}`,
    "A",
    { status: "approved" }
  );
  assert.equal(approve.status, 200);

  const duplicate = await api(
    "PATCH",
    `/api/ads/creatives/${creativeId}`,
    "A",
    { status: "approved" }
  );
  assert.equal(duplicate.status, 409);

  const listing = await api("GET", "/api/ads/creatives", "A");
  assert.equal(listing.status, 200);
  assert.equal(
    listing.data.items.find((c) => c.id === creativeId)?.status,
    "approved"
  );

  const delivered = await api(
    "GET",
    `/api/ads/delivery/next?placement_id=${placementId}`,
    "C"
  );
  assert.equal(delivered.status, 200);
  assert.ok(delivered.data.item);
  assert.equal(delivered.data.item.placement_id, placementId);

  const deliveredCreative = listing.data.items.find(
    (c) => c.id === delivered.data.item.creative_id
  );
  assert.equal(deliveredCreative?.status, "approved");

  const audits = await api("GET", "/api/ads/audit", "A");
  assert.equal(audits.status, 200);

  const creativeAudits = audits.data.items.filter(
    (a) => a.target_id === creativeId
  );
  assert.equal(creativeAudits.length, 2);

  const rejected = await api("POST", "/api/ads/creatives", "B", {
    campaign_id: campaignId,
    title: `PR7 rejected ${nonce}`,
    image_url: "https://example.com/rejected.png",
    target_url: "https://example.com/rejected"
  });
  assert.equal(rejected.status, 201);

  const reject = await api(
    "PATCH",
    `/api/ads/creatives/${rejected.data.id}`,
    "A",
    { status: "rejected" }
  );
  assert.equal(reject.status, 200);

  const afterRejection = await api(
    "GET",
    `/api/ads/delivery/next?placement_id=${placementId}`,
    "C"
  );
  assert.equal(afterRejection.status, 200);
  assert.notEqual(
    afterRejection.data.item?.creative_id,
    rejected.data.id
  );

  t.diagnostic(`campaign=${campaignId}`);
  t.diagnostic(`creative=${creativeId}`);
  t.diagnostic(`placement=${placementId}`);
});
