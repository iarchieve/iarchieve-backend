import test from "node:test";
import assert from "node:assert/strict";
import { handleVerificationAssessment } from "../src/modules/ads/verification-assess.mjs";

const claimId = "123e4567-e89b-42d3-a456-426614174000";
const evidence = "b".repeat(64);
const verifierId = "verifier-test";

async function createFixture({ active = true, changes = 1 } = {}) {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const calls = [];

  const db = {
    calls,
    prepare(sql) {
      return {
        bind(...params) {
          this.params = params;
          return this;
        },
        async first() {
          if (sql.includes("ads_verifier_registry")) {
            return active
              ? { public_key_jwk: JSON.stringify(publicJwk) }
              : null;
          }
          throw new Error("Unexpected query");
        },
        async run() {
          calls.push({ sql, params: this.params });
          return { meta: { changes } };
        }
      };
    }
  };

  async function signed({
    verdict = "accepted",
    claim_id = claimId
  } = {}) {
    const data = {
      claim_id,
      verifier_id: verifierId,
      verdict,
      evidence_digest: evidence
    };

    const canonical = [
      "iarchieve.ads.assessment.v1",
      data.claim_id,
      data.verifier_id,
      data.verdict,
      data.evidence_digest
    ].join("\n");

    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        new TextEncoder().encode(canonical)
      )
    );

    data.signature = Buffer.from(signature)
      .toString("base64url");

    return data;
  }

  async function call(data) {
    return handleVerificationAssessment(
      new Request("https://example.test/api/ads/verifications/assess", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      }),
      { ADS_DB: db }
    );
  }

  return { db, call, signed };
}

test("valid P-256 signature records a nonbillable assessment", async () => {
  const f = await createFixture();
  const response = await f.call(await f.signed());

  assert.equal(response.status, 201);
  const data = await response.json();
  assert.equal(data.assessment_recorded, true);
  assert.equal(data.final_verification, false);
  assert.equal(data.billable, false);
  assert.equal(f.db.calls.length, 1);
});

test("modified verdict invalidates signature", async () => {
  const f = await createFixture();
  const data = await f.signed();
  data.verdict = "rejected";

  const response = await f.call(data);
  assert.equal(response.status, 403);
  assert.equal(f.db.calls.length, 0);
});

test("unknown verifier cannot submit assessments", async () => {
  const f = await createFixture({ active: false });
  const response = await f.call(await f.signed());

  assert.equal(response.status, 403);
  assert.equal(f.db.calls.length, 0);
});

test("duplicate assessment is rejected", async () => {
  const f = await createFixture({ changes: 0 });
  const response = await f.call(await f.signed());

  assert.equal(response.status, 409);
});

test("unsigned assessment is rejected", async () => {
  const f = await createFixture();
  const data = await f.signed();
  delete data.signature;

  const response = await f.call(data);
  assert.equal(response.status, 422);
  assert.equal(f.db.calls.length, 0);
});