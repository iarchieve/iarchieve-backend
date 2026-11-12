import test from "node:test";
import assert from "node:assert/strict";
import { handleLoveSessionIssue } from "../src/modules/ads/love-session-issue.mjs";

const secret = "a".repeat(64);
const claimId = "123e4567-e89b-42d3-a456-426614174000";
const digest = "b".repeat(64);

function fixture(changes = 1) {
  const calls = [];
  const db = {
    prepare(sql) {
      return {
        bind(...values) {
          this.values = values;
          return this;
        },
        async run() {
          calls.push({ sql, values: this.values });
          return { meta: { changes } };
        }
      };
    }
  };

  function send(body, authorization = `Bearer ${secret}`) {
    return handleLoveSessionIssue(
      new Request("https://example.test/api/ads/admin/love-sessions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: authorization
        },
        body: JSON.stringify(body)
      }),
      { ADS_ADMIN_TOKEN: secret, ADS_DB: db }
    );
  }

  return { calls, send };
}

const input = {
  claim_id: claimId,
  verifier_id: "verifier-test",
  envelope_digest: digest
};

test("admin issues a nonbillable one-time session", async () => {
  const f = fixture();
  const response = await f.send(input);
  assert.equal(response.status, 201);

  const data = await response.json();
  assert.match(data.session_id, /^[0-9a-f-]{36}$/);
  assert.match(data.session_nonce, /^[0-9a-f]{32}$/);
  assert.equal(data.status, "issued");
  assert.equal(data.final_verification, false);
  assert.equal(data.billable, false);
  assert.equal(f.calls.length, 1);
  assert.match(f.calls[0].sql, /NOT EXISTS/);
});

test("unauthenticated issuance is blocked", async () => {
  const f = fixture();
  const response = await f.send(input, "");
  assert.equal(response.status, 401);
  assert.equal(f.calls.length, 0);
});

test("invalid digest is rejected", async () => {
  const f = fixture();
  const response = await f.send({
    ...input, envelope_digest: "invalid"
  });
  assert.equal(response.status, 422);
  assert.equal(f.calls.length, 0);
});

test("extra fields are rejected", async () => {
  const f = fixture();
  const response = await f.send({
    ...input, billable: true
  });
  assert.equal(response.status, 422);
});

test("unavailable claim or verifier returns conflict", async () => {
  const f = fixture(0);
  const response = await f.send(input);
  assert.equal(response.status, 409);
});

test("different requests generate distinct session values", async () => {
  const f = fixture();
  const a = await (await f.send(input)).json();
  const b = await (await f.send(input)).json();
  assert.notEqual(a.session_id, b.session_id);
  assert.notEqual(a.session_nonce, b.session_nonce);
});