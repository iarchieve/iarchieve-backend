import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { handleLoveLifecycle } from '../src/modules/ads/love-lifecycle.mjs';
import { createProtectedProof, generateProofKey } from '../src/modules/ads/love-proof.mjs';
import { evidenceDigest, protectedEnvelopeDigest } from '../src/modules/ads/love-evidence-binding.mjs';

// Explicit WebCrypto fallback for Node 22 and older runtimes.
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const token = 'a'.repeat(64);
const claim = '123e4567-e89b-42d3-a456-426614174000';
const rid = '223e4567-e89b-42d3-a456-426614174000';
const verifier = 'verifier-lifecycle';
const nonce = 'c'.repeat(32);
const expiry = new Date(Date.now() + 600000).toISOString().replace('T', ' ').slice(0, 19);
const root = 'https://example.test/api/ads/admin/love-reservations';

function mock({ changes = 1, row = { id: rid, claim_id: claim, verifier_id: verifier, session_nonce: nonce, expires_at: expiry } } = {}) {
  const queries = [];
  const db = {
    prepare(sql) {
      const call = { sql, bind: [] };
      queries.push(call);
      return {
        bind(...values) { call.bind = values; return this; },
        async run() { return { meta: { changes } }; },
        async first() { return row; }
      };
    }
  };
  const env = { ADS_ADMIN_TOKEN: token, ADS_DB: db };
  function post(path, input, auth = `Bearer ${token}`) {
    return handleLoveLifecycle(new Request(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: auth },
      body: JSON.stringify(input)
    }), env);
  }
  return { post, queries };
}
async function proofFixture(overrides = {}) {
  const proof = 'LOVE evidence lifecycle test';
  const key = generateProofKey();
  const digest = await evidenceDigest(proof);
  return createProtectedProof({ claim_id: claim, verifier_id: verifier, session_nonce: nonce,
    expires_at: new Date(Date.parse(expiry + 'Z') - 1000).toISOString(), evidence_digest: digest, proof, ...overrides }, key);
}

test('creates a reserved server nonce, no billing', async () => {
  const x = mock();
  const r = await x.post(root, { claim_id: claim, verifier_id: verifier });
  assert.equal(r.status, 201);
  const body = await r.json();
  assert.equal(body.status, 'reserved');
  assert.match(body.session_nonce, /^[0-9a-f]{32}$/);
  assert.equal(body.billable, false);
  assert.match(x.queries[0].sql, /ads_love_evidence_reservations/);
});
test('unauthorized requests do not read/write the database', async () => {
  const x = mock();
  assert.equal((await x.post(root, { claim_id: claim, verifier_id: verifier }, '')).status, 401);
  assert.equal(x.queries.length, 0);
});
test('invalid body rejected', async () => {
  const x = mock();
  assert.equal((await x.post(root, { claim_id: claim, verifier_id: verifier, billable: true })).status, 422);
  assert.equal(x.queries.length, 0);
});
test('duplicate reservation conflict', async () => {
  const x = mock({ changes: 0 });
  assert.equal((await x.post(root, { claim_id: claim, verifier_id: verifier })).status, 409);
});
test('finalizes by recomputing envelope digest, not trusting caller digest', async () => {
  const x = mock();
  const envelope = await proofFixture();
  const r = await x.post(`${root}/${rid}/finalize`, { envelope });
  assert.equal(r.status, 201);
  const body = await r.json();
  assert.equal(body.envelope_digest, await protectedEnvelopeDigest(envelope));
  assert.equal(body.reservation_status, 'finalized');
  assert.equal(body.billable, false);
  assert.equal(x.queries.length, 2);
  assert.match(x.queries[1].sql, /INSERT INTO ads_love_verification_sessions/);
  assert.equal(x.queries[1].bind[0], body.envelope_digest);
});
test('wrong server nonce rejected before session creation', async () => {
  const x = mock();
  const envelope = await proofFixture({ session_nonce: 'd'.repeat(32) });
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope })).status, 403);
  assert.equal(x.queries.length, 1);
});
test('incorrect verifier rejected', async () => {
  const x = mock();
  const envelope = await proofFixture({ verifier_id: 'other-verifier' });
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope })).status, 403);
});
test('forged client supplied digest is rejected as an unknown field', async () => {
  const x = mock();
  const envelope = await proofFixture();
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope, envelope_digest: 'a'.repeat(64) })).status, 422);
});
test('expiry after reservation expiry rejected', async () => {
  const x = mock();
  const envelope = await proofFixture();
  envelope.expires_at = new Date(Date.parse(expiry + 'Z') + 3000).toISOString();
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope })).status, 403);
});
test('already expired or absent reservation rejected', async () => {
  const x = mock({ row: null });
  const envelope = await proofFixture();
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope })).status, 409);
});
test('replayed finalization rejected by zero-row insert', async () => {
  const x = mock({ changes: 0 });
  const envelope = await proofFixture();
  assert.equal((await x.post(`${root}/${rid}/finalize`, { envelope })).status, 409);
});
