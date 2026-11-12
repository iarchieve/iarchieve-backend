import test from "node:test";
import assert from "node:assert/strict";
import { handleAdsDeliveryIssue } from "../src/modules/ads/delivery-issue.mjs";

const token = "a".repeat(64);

function db({ placement = true, ad = true } = {}) {
  const inserts = [];

  return {
    inserts,
    prepare(sql) {
      return {
        params: [],
        bind(...values) {
          this.params = values;
          return this;
        },
        async first() {
          if (sql.includes("ads_publisher_credentials")) {
            return { publisher_id: "pub-1" };
          }

          if (sql.includes("FROM ads_placements p")) {
            return placement
              ? { id: "placement-1", format: "display" }
              : null;
          }

          if (sql.includes("FROM ads_campaigns c")) {
            return ad ? {
              campaign_id: "campaign-1",
              creative_id: "creative-1",
              name: "Test Campaign",
              format: "display",
              title: "Test Creative",
              image_url: "https://example.com/a.png",
              target_url: "https://example.com"
            } : null;
          }

          throw new Error("Unexpected query");
        },
        async run() {
          inserts.push({ sql, params: this.params });
          return { success: true };
        }
      };
    }
  };
}

function request(body, authorized = true) {
  return new Request("https://example.test/api/ads/delivery/issue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authorized ? {
        Authorization: `Bearer ${token}`
      } : {})
    },
    body: JSON.stringify(body)
  });
}

test("issues a non-billable delivery ID", async () => {
  const database = db();

  const response = await handleAdsDeliveryIssue(
    request({ placement_id: "placement-1" }),
    { ADS_DB: database }
  );

  assert.equal(response.status, 201);

  const data = await response.json();

  assert.match(data.delivery_request_id, /^[a-f0-9-]{36}$/);
  assert.equal(data.billable, false);
  assert.equal(data.verification_status, "not_submitted");
  assert.equal(data.item.creative_id, "creative-1");
  assert.equal(database.inserts.length, 1);
  assert.equal(database.inserts[0].params[0], data.delivery_request_id);
});

test("rejects unauthenticated delivery issuance", async () => {
  const database = db();
  const response = await handleAdsDeliveryIssue(
    request({ placement_id: "placement-1" }, false),
    { ADS_DB: database }
  );

  assert.equal(response.status, 401);
  assert.equal(database.inserts.length, 0);
});

test("rejects unavailable placement", async () => {
  const database = db({ placement: false });
  const response = await handleAdsDeliveryIssue(
    request({ placement_id: "placement-1" }),
    { ADS_DB: database }
  );

  assert.equal(response.status, 404);
  assert.equal(database.inserts.length, 0);
});

test("returns empty selection without creating an event", async () => {
  const database = db({ ad: false });
  const response = await handleAdsDeliveryIssue(
    request({ placement_id: "placement-1" }),
    { ADS_DB: database }
  );

  assert.equal(response.status, 200);
  assert.equal((await response.json()).item, null);
  assert.equal(database.inserts.length, 0);
});

test("rejects extra request fields", async () => {
  const database = db();
  const response = await handleAdsDeliveryIssue(
    request({
      placement_id: "placement-1",
      price: 1
    }),
    { ADS_DB: database }
  );

  assert.equal(response.status, 422);
  assert.equal(database.inserts.length, 0);
});