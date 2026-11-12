import test from "node:test";
import assert from "node:assert/strict";
import { handleImpressionClaim } from "../src/modules/ads/impression-claim.mjs";

const token = "a".repeat(64);
const deliveryId = "123e4567-e89b-42d3-a456-426614174000";
const digest = "b".repeat(64);

function createDb({ available = true, changes = 1 } = {}) {
  const writes = [];

  return {
    writes,
    prepare(sql) {
      return {
        params: [],
        bind(...params) {
          this.params = params;
          return this;
        },
        async first() {
          if (sql.includes("ads_publisher_credentials")) {
            return { publisher_id: "publisher-test" };
          }
          if (sql.includes("FROM ads_delivery_requests d")) {
            return available ? { id: deliveryId } : null;
          }
          throw new Error("Unexpected SELECT");
        },
        async run() {
          writes.push({ sql, params: this.params });
          return { meta: { changes } };
        }
      };
    }
  };
}

function makeRequest(body, authorized = true) {
  return new Request(
    "https://example.test/api/ads/impressions/claim",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authorized
          ? { Authorization: `Bearer ${token}` }
          : {})
      },
      body: JSON.stringify(body)
    }
  );
}

const good = {
  delivery_request_id: deliveryId,
  proof_digest: digest
};

test("accepts evidence as pending and nonbillable", async () => {
  const db = createDb();
  const response = await handleImpressionClaim(
    makeRequest(good),
    { ADS_DB: db }
  );

  assert.equal(response.status, 202);
  const data = await response.json();
  assert.equal(data.verification_status, "pending");
  assert.equal(data.billable, false);
  assert.equal(db.writes.length, 1);
  assert.match(db.writes[0].sql, /INSERT OR IGNORE/);
  assert.match(db.writes[0].sql, /expires_at > CURRENT_TIMESTAMP/);
});

test("rejects unauthenticated claims", async () => {
  const db = createDb();
  const response = await handleImpressionClaim(
    makeRequest(good, false),
    { ADS_DB: db }
  );
  assert.equal(response.status, 401);
  assert.equal(db.writes.length, 0);
});

test("rejects unknown or expired issuance", async () => {
  const db = createDb({ available: false });
  const response = await handleImpressionClaim(
    makeRequest(good),
    { ADS_DB: db }
  );
  assert.equal(response.status, 404);
  assert.equal(db.writes.length, 0);
});

test("rejects duplicate or concurrent claims", async () => {
  const db = createDb({ changes: 0 });
  const response = await handleImpressionClaim(
    makeRequest(good),
    { ADS_DB: db }
  );
  assert.equal(response.status, 409);
  assert.equal(db.writes.length, 1);
});

test("rejects malformed proof digest", async () => {
  const db = createDb();
  const response = await handleImpressionClaim(
    makeRequest({ ...good, proof_digest: "invalid" }),
    { ADS_DB: db }
  );
  assert.equal(response.status, 422);
  assert.equal(db.writes.length, 0);
});

test("rejects unexpected billing fields", async () => {
  const db = createDb();
  const response = await handleImpressionClaim(
    makeRequest({ ...good, charge_krw: 100 }),
    { ADS_DB: db }
  );
  assert.equal(response.status, 422);
  assert.equal(db.writes.length, 0);
});