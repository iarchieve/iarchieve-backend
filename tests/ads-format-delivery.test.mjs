import test from "node:test";
import assert from "node:assert/strict";
import { handleAdsDelivery } from "../src/modules/ads/delivery.mjs";

const secret = "C".repeat(64);

function createEnv(format, availableFormats = ["display", "video", "native"],
                   placementStatus = "approved") {
  const calls = [];

  const db = {
    prepare(sql) {
      const statement = {
        bind(...params) {
          calls.push({ sql, params });
          return statement;
        },
        async first() {
          if (sql.includes("FROM ads_placements")) {
            return {
              id: "placement-test",
              publisher_id: "pub-test-001",
              status: placementStatus,
              format
            };
          }

          if (sql.includes("FROM ads_campaigns")) {
            assert.match(sql, /a\.format\s*=\s*\?/);
            assert.match(sql, /a\.status='active'/);
            assert.match(sql, /c\.status='approved'/);

            const bound = calls.at(-1)?.params[0];
            assert.equal(bound, format);

            if (!availableFormats.includes(bound)) return null;

            return {
              id: `campaign-${bound}`,
              name: `Campaign ${bound}`,
              format: bound,
              creative_id: `creative-${bound}`,
              title: `Creative ${bound}`,
              image_url: "https://example.com/ad.png",
              target_url: "https://example.com/"
            };
          }

          throw new Error(`Unexpected query: ${sql}`);
        }
      };
      return statement;
    }
  };

  return {
    env: {
      ADS_PUBLISHER_TOKEN: secret,
      ADS_DB: db
    },
    calls
  };
}

function request(auth = true) {
  return new Request(
    "http://localhost/api/ads/delivery/next?placement_id=placement-test",
    {
      headers: auth
        ? { Authorization: `Bearer ${secret}` }
        : {}
    }
  );
}

for (const format of ["display", "video", "native"]) {
  test(`delivery matches ${format} placement`, async () => {
    const { env } = createEnv(format);
    const response = await handleAdsDelivery(request(), env);

    assert.equal(response.status, 200);
    const data = await response.json();

    assert.equal(data.item.format, format);
    assert.equal(data.item.campaign_id, `campaign-${format}`);
    assert.equal(data.item.creative_id, `creative-${format}`);
    assert.equal(data.item.placement_id, "placement-test");
  });
}

test("delivery excludes campaigns of a different format", async () => {
  const { env } = createEnv("video", ["display", "native"]);
  const response = await handleAdsDelivery(request(), env);

  assert.equal(response.status, 200);
  assert.equal((await response.json()).item, null);
});

test("delivery blocks unapproved placements", async () => {
  const { env } = createEnv("display", ["display"], "pending");
  const response = await handleAdsDelivery(request(), env);

  assert.equal(response.status, 409);
  assert.equal(
    (await response.json()).error,
    "placement_not_approved"
  );
});

test("delivery requires publisher authentication", async () => {
  const { env } = createEnv("display");
  const response = await handleAdsDelivery(request(false), env);

  assert.equal(response.status, 401);
});
