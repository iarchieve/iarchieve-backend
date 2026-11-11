import test from "node:test";
import assert from "node:assert/strict";
import { handleAdsCreatives } from "../src/modules/ads/creatives.mjs";

const token = "A".repeat(64);

test("creative API requires authentication", async () => {
  const result = await handleAdsCreatives(
    new Request("http://localhost/api/ads/creatives"),
    {}
  );
  assert.equal(result.status, 401);
});

test("creative API requires database", async () => {
  const result = await handleAdsCreatives(
    new Request("http://localhost/api/ads/creatives", {
      headers: { Authorization: `Bearer ${token}` }
    }),
    { ADS_ADMIN_TOKEN: token }
  );
  assert.equal(result.status, 503);
});

test("creative API rejects invalid URLs", async () => {
  const result = await handleAdsCreatives(
    new Request("http://localhost/api/ads/creatives", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        campaign_id: "c1",
        title: "Demo",
        image_url: "javascript:alert(1)",
        target_url: "https://example.com"
      })
    }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: {} }
  );
  assert.equal(result.status, 422);
});

test("advertiser cannot approve creative", async () => {
  const result = await handleAdsCreatives(
    new Request("http://localhost/api/ads/creatives/c1", {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ status: "approved" })
    }),
    { ADS_ADVERTISER_TOKEN: token, ADS_DB: {} }
  );
  assert.equal(result.status, 403);
});
