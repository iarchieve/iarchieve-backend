import test from "node:test";
import assert from "node:assert/strict";
import {
  generateProofKey,
  createProtectedProof,
  openProtectedProof
} from "../src/modules/ads/love-proof.mjs";

const claim_id = "123e4567-e89b-42d3-a456-426614174000";
const verifier_id = "verifier-alpha";
const evidence_digest = "a".repeat(64);

async function fixture() {
  const key = generateProofKey();
  const input = {
    claim_id,
    verifier_id,
    evidence_digest,
    proof: "Encrypted advertising evidence fixture"
  };
  const envelope = await createProtectedProof(input, key);
  return { key, input, envelope };
}

test("encrypts and decrypts bound proof", async () => {
  const f = await fixture();

  assert.equal(f.envelope.algorithm, "AES-256-GCM");
  assert.ok(!JSON.stringify(f.envelope).includes(f.input.proof));

  const result = await openProtectedProof(
    f.envelope, f.key, f.input
  );
  assert.equal(result, f.input.proof);
});

test("rejects a different verifier", async () => {
  const f = await fixture();
  await assert.rejects(
    openProtectedProof(f.envelope, f.key, {
      ...f.input, verifier_id: "verifier-beta"
    }),
    /love_binding_mismatch/
  );
});

test("rejects a different claim", async () => {
  const f = await fixture();
  await assert.rejects(
    openProtectedProof(f.envelope, f.key, {
      ...f.input,
      claim_id: "223e4567-e89b-42d3-a456-426614174000"
    }),
    /love_binding_mismatch/
  );
});

test("rejects modified session nonce", async () => {
  const f = await fixture();
  const modified = {
    ...f.envelope,
    session_nonce: "f".repeat(32)
  };

  await assert.rejects(
    openProtectedProof(modified, f.key, f.input)
  );
});

test("rejects tampered ciphertext", async () => {
  const f = await fixture();
  const modified = {
    ...f.envelope,
    ciphertext: (
      f.envelope.ciphertext[0] === "A" ? "B" : "A"
    ) + f.envelope.ciphertext.slice(1)
  };

  await assert.rejects(
    openProtectedProof(modified, f.key, f.input)
  );
});

test("rejects an incorrect key", async () => {
  const f = await fixture();
  await assert.rejects(
    openProtectedProof(f.envelope, generateProofKey(), f.input)
  );
});

test("rejects expired proof", async () => {
  const f = await fixture();

  await assert.rejects(
    openProtectedProof(
      f.envelope,
      f.key,
      f.input,
      Date.parse(f.envelope.expires_at) + 1
    ),
    /session_expired_or_invalid/
  );
});

test("uses unique nonce and IV for each proof", async () => {
  const key = generateProofKey();
  const input = {
    claim_id,
    verifier_id,
    evidence_digest,
    proof: "Same evidence"
  };

  const a = await createProtectedProof(input, key);
  const b = await createProtectedProof(input, key);

  assert.notEqual(a.session_nonce, b.session_nonce);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext);
});