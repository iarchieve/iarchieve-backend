import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/http/worker.mjs";

const response = (path, method = "GET", env = {}) =>
  worker.fetch(
    new Request(`http://localhost${path}`, { method }),
    env
  );

test("existing health endpoint remains available", async () => {
  const result = await response("/health");
  assert.equal(result.status, 200);
  assert.equal((await result.json()).status, "ok");
});

test("health rejects unsupported methods", async () => {
  const result = await response("/health", "POST");
  assert.equal(result.status, 405);
});

test("removed report endpoint returns 404", async () => {
  const result = await response("/api/reports/draft");
  assert.equal(result.status, 404);
});

test("advertising API rejects unauthenticated access", async () => {
  const result = await response("/api/ads/campaigns");
  assert.equal(result.status, 401);
});

test("advertising API rejects missing D1 binding", async () => {
  const token = "A".repeat(64);
  const result = await worker.fetch(
    new Request("http://localhost/api/ads/campaigns", {
      headers: { Authorization: `Bearer ${token}` }
    }),
    { ADS_ADMIN_TOKEN: token }
  );
  assert.equal(result.status, 503);
});

test("unknown route returns 404", async () => {
  const result = await response("/api/unknown");
  assert.equal(result.status, 404);
});
