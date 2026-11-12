import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {
  evaluateTasHandoff,
  evaluateStoredTasHandoff
} from '../src/modules/ads/tas-engine.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const hash = c => c.repeat(64);

const assessment = (id, controller, verdict = 'accepted') => ({
  assessment_id: id,
  verifier_id: id,
  verdict,
  evidence_digest: hash('a'),
  assessment_digest: hash('b'),
  love_session_id: id,
  verifier_status: 'active',
  controller_id: controller,
  affiliation_evidence_digest: hash('c')
});

const payload = (assessments, conflicts = []) => ({
  schema: 'iarchieve.ads.tas-handoff.v1',
  claim_id: 'claim',
  impression_proof_digest: hash('d'),
  claim_verification_status: 'pending',
  assessments,
  declared_controller_conflicts: conflicts,
  independence_certified: false,
  tas_adjudicated: false,
  final_verification: false,
  billable: false
});

const conflict = (a, b) => ({
  controller_a: a,
  controller_b: b,
  evidence_digest: hash('e')
});

test('independent quorum is provisional and non-billable', () => {
  const result = evaluateTasHandoff(payload([
    assessment('a','a'), assessment('b','b'), assessment('c','c')
  ]));
  assert.equal(result.state, 'provisional_accept');
  assert.equal(result.billable, false);
  assert.equal(result.tas_adjudicated, false);
});

test('same controller cannot vote twice', () => {
  const result = evaluateTasHandoff(payload([
    assessment('a','a'), assessment('b','a'), assessment('c','b')
  ]));
  assert.equal(result.state, 'insufficient_quorum');
});

test('conflicting controllers do not form a quorum', () => {
  const result = evaluateTasHandoff(payload([
    assessment('a','a'), assessment('b','b'), assessment('c','c')
  ], [conflict('a','b')]));
  assert.equal(result.state, 'insufficient_quorum');
});

test('missing affiliation is blocked', () => {
  const p = payload([assessment('a','a')]);
  p.assessments[0].controller_id = null;
  assert.equal(evaluateTasHandoff(p).state, 'blocked');
});

test('revoked verifier is blocked', () => {
  const p = payload([assessment('a','a')]);
  p.assessments[0].verifier_status = 'revoked';
  assert.equal(evaluateTasHandoff(p).state, 'blocked');
});

test('duplicate verifier is blocked', () => {
  assert.equal(evaluateTasHandoff(payload([
    assessment('a','a'), assessment('a','b')
  ])).state, 'blocked');
});

test('controller disagreement is blocked', () => {
  assert.equal(evaluateTasHandoff(payload([
    assessment('a','a'), assessment('b','a','rejected')
  ])).reason, 'controller_disagreement');
});

test('opposing quorums are disputed', () => {
  const all = ['a','b','c'].map(x => assessment(x,x))
    .concat(['d','e','f'].map(x => assessment(x,x,'rejected')));
  assert.equal(evaluateTasHandoff(payload(all)).state, 'disputed');
});

test('empty snapshot is blocked', () => {
  assert.equal(evaluateTasHandoff(null).state, 'blocked');
  assert.equal(evaluateTasHandoff(payload([])).state, 'blocked');
});

test('invalid conflict is blocked', () => {
  assert.equal(evaluateTasHandoff(payload([
    assessment('a','a')
  ], [conflict('z','a')])).reason, 'invalid_conflicts');
});

test('stored digest protects handoff integrity', async () => {
  const serialized = JSON.stringify(payload([
    assessment('a','a'), assessment('b','b'), assessment('c','c')
  ]));

  const digestBytes = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(serialized)
  );

  const digest = Array.from(new Uint8Array(digestBytes),
    x => x.toString(16).padStart(2,'0')).join('');

  const valid = await evaluateStoredTasHandoff({
    payload_json: serialized, payload_digest: digest
  });

  assert.equal(valid.state, 'provisional_accept');

  const invalid = await evaluateStoredTasHandoff({
    payload_json: serialized + ' ', payload_digest: digest
  });

  assert.equal(invalid.reason, 'handoff_integrity_failure');
});
