import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/http/worker.mjs";

test("legacy verification route is disabled", async () => {
  const response = await worker.fetch(
    new Request(
      "https://example.test/api/ads/verifications/assess",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          claim_id: "example",
          verifier_id: "legacy"
        })
      }
    ),
    {}
  );

  assert.equal(response.status, 410);

  const data = await response.json();
  assert.equal(data.error, "legacy_verification_disabled");
  assert.equal(
    data.replacement,
    "/api/ads/verifications/love-assess"
  );
});

test("LOVE route remains registered", async () => {
  const response = await worker.fetch(
    new Request(
      "https://example.test/api/ads/verifications/love-assess",
      { method: "POST" }
    ),
    {}
  );

  assert.equal(response.status, 503);
  assert.equal(
    (await response.json()).error,
    "database_unavailable"
  );
});

test("legacy route cannot be used through GET", async () => {
  const response = await worker.fetch(
    new Request(
      "https://example.test/api/ads/verifications/assess"
    ),
    {}
  );

  assert.equal(response.status, 410);
});