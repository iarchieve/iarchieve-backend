import test from "node:test";
import assert from "node:assert/strict";
import { handleAdsDelivery } from "../src/modules/ads/delivery.mjs";

const token = "C".repeat(64);

function environment(accountStatus) {
  let queries = [];

  const env = {
    ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true",
    ADS_DB: {
      prepare(sql) {
        queries.push(sql);

        const statement = {
          bind() {
            return statement;
          },

          async first() {
            if (sql.includes("FROM ads_placements")) {
              assert.match(sql, /ads_accounts\.role='publisher'/);
              assert.match(sql, /ads_accounts\.status='active'/);
              assert.match(sql, /ads_accounts\.id=ads_placements\.publisher_id/);

              if (accountStatus !== "active") return null;

              return {
                id: "placement-1",
                publisher_id: "pub-test-001",
                status: "approved",
                format: "display"
              };
            }

            if (sql.includes("FROM ads_campaigns")) {
              return {
                id: "campaign-1",
                name: "Demo",
                format: "display",
                creative_id: "creative-1",
                title: "Demo creative",
                image_url: "https://example.com/image.png",
                target_url: "https://example.com/"
              };
            }

            throw new Error("Unexpected SQL");
          }
        };

        return statement;
      }
    }
  };

  return { env, queries };
}

for (const status of ["pending", "suspended", "missing"]) {
  test(`publisher ${status} cannot receive delivery`, async () => {
    const { env, queries } = environment(status);

    const response = await handleAdsDelivery(
      new Request(
        "http://localhost/api/ads/delivery/next?placement_id=placement-1",
        { headers: { Authorization: `Bearer ${token}` } }
      ),
      env
    );

    assert.equal(response.status, 404);
    assert.equal((await response.json()).error, "not_found");
    assert.equal(queries.length, 1);
  });
}

test("active publisher can receive approved creative", async () => {
  const { env, queries } = environment("active");

  const response = await handleAdsDelivery(
    new Request(
      "http://localhost/api/ads/delivery/next?placement_id=placement-1",
      { headers: { Authorization: `Bearer ${token}` } }
    ),
    env
  );

  assert.equal(response.status, 200);

  const body = await response.json();
  assert.equal(body.item.placement_id, "placement-1");
  assert.equal(body.item.creative_id, "creative-1");
  assert.equal(queries.length, 2);
});