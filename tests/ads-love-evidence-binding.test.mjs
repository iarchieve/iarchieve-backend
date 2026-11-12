import test from "node:test";
import assert from "node:assert/strict";
import {
  createProtectedProof,
  generateProofKey
} from "../src/modules/ads/love-proof.mjs";
import {
  evidenceDigest,
  protectedEnvelopeDigest,
  verifyProtectedEvidence
} from "../src/modules/ads/love-evidence-binding.mjs";

const claimId = "123e4567-e89b-42d3-a456-426614174000";
const sessionId = "223e4567-e89b-42d3-a456-426614174000";
const verifierId = "verifier-binding-test";
const nonce = "c".repeat(32);

async function fixture() {
  const key = generateProofKey();
  const proof = "Protected evidence for PoAE verification";
  const digest = await evidenceDigest(proof);

  const envelope = await createProtectedProof({
    claim_id: claimId,
    verifier_id: verifierId,
    evidence_digest: digest,
    session_nonce: nonce,
    proof
  }, key);

  const envelopeHash = await protectedEnvelopeDigest(envelope);

  const session = {
    id: sessionId,
    claim_id: claimId,
    verifier_id: verifierId,
    session_nonce: nonce,
    envelope_digest: envelopeHash,
    expires_at: new Date(Date.now() + 600000).toISOString(),
    status: "issued"
  };

  return { key, proof, envelope, session };
}

test("binds a server nonce to protected evidence", async () => {
  const f = await fixture();
  assert.equal(f.envelope.session_nonce, nonce);

  const result = await verifyProtectedEvidence(
    f.envelope, f.key, f.session
  );

  assert.equal(result.envelope_verified, true);
  assert.equal(result.evidence_verified, true);
  assert.equal(result.final_verification, false);
  assert.equal(result.billable, false);
});

test("envelope digest ignores JSON object property order", async () => {
  const f = await fixture();
  const reverse = Object.fromEntries(
    Object.entries(f.envelope).reverse()
  );

  assert.equal(
    await protectedEnvelopeDigest(reverse),
    f.session.envelope_digest
  );
});

test("rejects altered server session nonce", async () => {
  const f = await fixture();
  await assert.rejects(
    verifyProtectedEvidence(f.envelope, f.key, {
      ...f.session, session_nonce: "f".repeat(32)
    }),
    /session_binding_mismatch/
  );
});

test("rejects a different verifier", async () => {
  const f = await fixture();
  await assert.rejects(
    verifyProtectedEvidence(f.envelope, f.key, {
      ...f.session, verifier_id: "other-verifier"
    }),
    /session_binding_mismatch/
  );
});

test("rejects a different claim", async () => {
  const f = await fixture();
  await assert.rejects(
    verifyProtectedEvidence(f.envelope, f.key, {
      ...f.session,
      claim_id: "323e4567-e89b-42d3-a456-426614174000"
    }),
    /session_binding_mismatch/
  );
});

test("rejects a changed ciphertext", async () => {
  const f = await fixture();
  const changed = {
    ...f.envelope,
    ciphertext: (
      f.envelope.ciphertext[0] === "A" ? "B" : "A"
    ) + f.envelope.ciphertext.slice(1)
  };

  await assert.rejects(
    verifyProtectedEvidence(changed, f.key, f.session),
    /envelope_digest_mismatch/
  );
});

test("rejects modified envelope fields", async () => {
  const f = await fixture();
  await assert.rejects(
    protectedEnvelopeDigest({
      ...f.envelope,
      unexpected_field: "injected"
    }),
    /invalid_envelope_fields/
  );
});

test("rejects incorrect evidence digest even if re-encrypted", async () => {
  const f = await fixture();

  const changed = await createProtectedProof({
    claim_id: claimId,
    verifier_id: verifierId,
    session_nonce: nonce,
    evidence_digest: "f".repeat(64),
    proof: f.proof
  }, f.key);

  const changedSession = {
    ...f.session,
    envelope_digest: await protectedEnvelopeDigest(changed)
  };

  await assert.rejects(
    verifyProtectedEvidence(changed, f.key, changedSession),
    /evidence_digest_mismatch/
  );
});

test("rejects consumed sessions", async () => {
  const f = await fixture();
  await assert.rejects(
    verifyProtectedEvidence(f.envelope, f.key, {
      ...f.session, status: "consumed"
    }),
    /session_binding_mismatch/
  );
});

test("rejects expired sessions", async () => {
  const f = await fixture();
  await assert.rejects(
    verifyProtectedEvidence(
      f.envelope, f.key, f.session,
      Date.parse(f.session.expires_at) + 1
    ),
    /session_expired_or_invalid/
  );
});