import test from "node:test";
import assert from "node:assert/strict";
import {
  handleLoveAssessment,
  canonicalLoveAssessment
} from "../src/modules/ads/love-assess.mjs";

const claim_id = "123e4567-e89b-42d3-a456-426614174000";
const session_id = "223e4567-e89b-42d3-a456-426614174000";

async function fixture({ available = true, changes = 1 } = {}) {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const publicKey = await crypto.subtle.exportKey(
    "jwk", pair.publicKey
  );

  const writes = [];

  const db = {
    prepare(sql) {
      return {
        bind(...params) {
          this.params = params;
          return this;
        },
        async first() {
          if (!sql.includes("ads_love_verification_sessions")) {
            throw new Error("Unexpected query");
          }

          return available ? {
            id: session_id,
            session_nonce: "a".repeat(32),
            envelope_digest: "b".repeat(64),
            public_key_jwk: JSON.stringify(publicKey)
          } : null;
        },
        async run() {
          writes.push({ sql, params: this.params });
          return { meta: { changes } };
        }
      };
    }
  };

  async function signed() {
    const data = {
      claim_id,
      verifier_id: "verifier-love",
      session_id,
      session_nonce: "a".repeat(32),
      envelope_digest: "b".repeat(64),
      verdict: "accepted",
      evidence_digest: "c".repeat(64)
    };

    const bytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      new TextEncoder().encode(canonicalLoveAssessment(data))
    );

    data.signature = Buffer.from(bytes).toString("base64url");

    return data;
  }

  async function send(data) {
    return handleLoveAssessment(
      new Request("https://example.test/api/ads/verifications/love-assess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      }),
      { ADS_DB: db }
    );
  }

  return { db, writes, signed, send };
}

test("accepts signed LOVE assessment without billing", async () => {
  const f = await fixture();
  const response = await f.send(await f.signed());

  assert.equal(response.status, 201);

  const result = await response.json();

  assert.equal(result.signature_verified, true);
  assert.equal(result.session_consumed, true);
  assert.equal(result.final_verification, false);
  assert.equal(result.billable, false);
  assert.equal(f.writes.length, 1);
  assert.match(f.writes[0].sql, /love_session_id/);
});

test("changed verdict invalidates signature", async () => {
  const f = await fixture();
  const data = await f.signed();
  data.verdict = "rejected";

  const response = await f.send(data);

  assert.equal(response.status, 403);
  assert.equal(f.writes.length, 0);
});

test("changed session nonce is rejected", async () => {
  const f = await fixture();
  const data = await f.signed();
  data.session_nonce = "d".repeat(32);

  const response = await f.send(data);

  assert.equal(response.status, 403);
  assert.equal(f.writes.length, 0);
});

test("changed envelope digest is rejected", async () => {
  const f = await fixture();
  const data = await f.signed();
  data.envelope_digest = "e".repeat(64);

  const response = await f.send(data);

  assert.equal(response.status, 403);
  assert.equal(f.writes.length, 0);
});

test("unknown or expired session is rejected", async () => {
  const f = await fixture({ available: false });
  const response = await f.send(await f.signed());

  assert.equal(response.status, 409);
  assert.equal(f.writes.length, 0);
});

test("atomic insert failure never reports success", async () => {
  const f = await fixture({ changes: 0 });
  const response = await f.send(await f.signed());

  assert.equal(response.status, 409);
  assert.equal(f.writes.length, 1);
});

test("unsigned LOVE assessment is rejected", async () => {
  const f = await fixture();
  const data = await f.signed();
  delete data.signature;

  const response = await f.send(data);

  assert.equal(response.status, 422);
  assert.equal(f.writes.length, 0);
});