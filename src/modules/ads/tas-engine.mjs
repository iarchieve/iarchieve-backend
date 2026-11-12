const HEX = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const validId = x => typeof x === 'string' && ID.test(x);
const validHash = x => typeof x === 'string' && HEX.test(x);

const blocked = reason => ({
  state: 'blocked',
  reason,
  independence_certified: false,
  tas_adjudicated: false,
  final_verification: false,
  billable: false
});

export function evaluateTasHandoff(payload, {minimumIndependent = 3} = {}) {
  if (!Number.isInteger(minimumIndependent) ||
      minimumIndependent < 2 || minimumIndependent > 20)
    return blocked('invalid_policy');

  if (!payload ||
      payload.schema !== 'iarchieve.ads.tas-handoff.v1' ||
      payload.claim_verification_status !== 'pending' ||
      !validHash(payload.impression_proof_digest) ||
      !Array.isArray(payload.assessments) ||
      !Array.isArray(payload.declared_controller_conflicts) ||
      !payload.assessments.length ||
      payload.assessments.length > 200 ||
      payload.declared_controller_conflicts.length > 1000 ||
      payload.independence_certified !== false ||
      payload.tas_adjudicated !== false ||
      payload.final_verification !== false ||
      payload.billable !== false)
    return blocked('invalid_snapshot');

  const verifiers = new Set();
  const controllers = new Map();
  const conflicts = new Set();

  for (const a of payload.assessments) {
    if (!a || !validId(a.verifier_id) ||
        verifiers.has(a.verifier_id) ||
        !validHash(a.evidence_digest) ||
        !validHash(a.assessment_digest) ||
        !validId(a.controller_id) ||
        !validHash(a.affiliation_evidence_digest) ||
        a.verifier_status !== 'active' ||
        !['accepted', 'rejected'].includes(a.verdict) ||
        typeof a.love_session_id !== 'string' ||
        !a.love_session_id)
      return blocked('invalid_or_unverified_assessment');

    verifiers.add(a.verifier_id);

    if (!controllers.has(a.controller_id))
      controllers.set(a.controller_id, new Set());

    controllers.get(a.controller_id).add(a.verdict);
  }

  for (const c of payload.declared_controller_conflicts) {
    if (!c || !validId(c.controller_a) ||
        !validId(c.controller_b) ||
        c.controller_a >= c.controller_b ||
        !validHash(c.evidence_digest))
      return blocked('invalid_conflicts');

    conflicts.add(c.controller_a + ':' + c.controller_b);
  }

  for (const votes of controllers.values()) {
    if (votes.size !== 1)
      return blocked('controller_disagreement');
  }

  const ids = [...controllers.keys()].sort();

  if (ids.length > 20)
    return blocked('controller_limit');

  const edges = ids.map(() => 0);

  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      if (conflicts.has(ids[i] + ':' + ids[j])) {
        edges[i] |= (1 << j);
        edges[j] |= (1 << i);
      }
    }
  }

  let accepted = null;
  let rejected = null;

  for (let mask = 1; mask < (1 << ids.length); mask++) {
    const selected = [];
    let valid = true;

    for (let i = 0; i < ids.length; i++) {
      if (!(mask & (1 << i))) continue;

      if (edges[i] & mask) {
        valid = false;
        break;
      }

      selected.push(ids[i]);
    }

    if (!valid || selected.length < minimumIndependent)
      continue;

    const votes = selected.map(id => [...controllers.get(id)][0]);

    if (!votes.every(v => v === votes[0]))
      continue;

    if (votes[0] === 'accepted') {
      if (!accepted || selected.length > accepted.length)
        accepted = selected;
    } else {
      if (!rejected || selected.length > rejected.length)
        rejected = selected;
    }
  }

  const state = accepted && rejected ? 'disputed'
    : accepted ? 'provisional_accept'
    : rejected ? 'provisional_reject'
    : 'insufficient_quorum';

  const selected = state === 'provisional_accept' ? accepted
    : state === 'provisional_reject' ? rejected : null;

  return {
    state,
    assessment_count: payload.assessments.length,
    controller_count: ids.length,
    independent_controller_upper_bound: ids.length,
    provisional_quorum: selected ? {
      controller_ids: selected,
      verdict: state === 'provisional_accept' ? 'accepted' : 'rejected'
    } : null,
    source: 'admin_declared_unverified',
    independence_certified: false,
    tas_adjudicated: false,
    final_verification: false,
    billable: false
  };
}

export async function evaluateStoredTasHandoff(row, options) {
  if (!row || typeof row.payload_json !== 'string' ||
      !validHash(row.payload_digest))
    return blocked('invalid_stored_record');

  const bytes = new TextEncoder().encode(row.payload_json);
  const digestBytes = await crypto.subtle.digest('SHA-256', bytes);

  const digest = Array.from(new Uint8Array(digestBytes),
    x => x.toString(16).padStart(2, '0')).join('');

  if (digest !== row.payload_digest)
    return blocked('handoff_integrity_failure');

  let payload;
  try {
    payload = JSON.parse(row.payload_json);
  } catch {
    return blocked('invalid_snapshot_json');
  }

  return evaluateTasHandoff(payload, options);
}
