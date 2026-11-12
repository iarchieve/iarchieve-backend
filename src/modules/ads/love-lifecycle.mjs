import { protectedEnvelopeDigest } from './love-evidence-binding.mjs';

const encoder = new TextEncoder();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const reply = (data, status = 200) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });

function authorized(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(request.headers.get('Authorization') || '');
  const secret = env.ADS_ADMIN_TOKEN;
  if (!match || typeof secret !== 'string' || !HEX64.test(secret.toLowerCase())) return false;
  let diff = 0;
  const actual = match[1].toLowerCase();
  const expected = secret.toLowerCase();
  for (let i = 0; i < 64; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

async function readJson(request, maxBytes = 16384) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) {
    return { error: 'content_type_required', status: 400 };
  }
  const length = request.headers.get('Content-Length');
  if (length !== null && (!Number.isSafeInteger(Number(length)) || Number(length) > maxBytes || Number(length) < 0)) {
    return { error: 'body_too_large', status: 413 };
  }
  try {
    // Bound bytes during streaming, not after materializing an arbitrarily large request.
    const reader = request.body?.getReader();
    if (!reader) return { error: 'invalid_json', status: 400 };
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { error: 'body_too_large', status: 413 };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { error: 'invalid_json', status: 400 };
    return { data };
  } catch { return { error: 'invalid_json', status: 400 }; }
}

function hexNonce() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
}
function utcSqlDate(ms) { return new Date(ms).toISOString().replace('T', ' ').slice(0, 19); }

export async function handleLoveLifecycle(request, env) {
  if (request.method !== 'POST') return reply({ error: 'method_not_allowed' }, 405);
  if (!authorized(request, env)) return reply({ error: 'unauthorized' }, 401);
  if (!env.ADS_DB) return reply({ error: 'database_unavailable' }, 503);

  const path = new URL(request.url).pathname;
  const root = '/api/ads/admin/love-reservations';
  const finalize = /^\/api\/ads\/admin\/love-reservations\/([^/]+)\/finalize$/.exec(path);
  if (path !== root && !finalize) return reply({ error: 'not_found' }, 404);

  const parsed = await readJson(request);
  if (parsed.error) return reply({ error: parsed.error }, parsed.status);
  const input = parsed.data;

  if (path === root) {
    if (Object.keys(input).sort().join(',') !== 'claim_id,verifier_id' ||
        typeof input.claim_id !== 'string' || typeof input.verifier_id !== 'string' ||
        !UUID.test(input.claim_id) || !ID.test(input.verifier_id)) {
      return reply({ error: 'invalid_reservation' }, 422);
    }
    const reservationId = crypto.randomUUID();
    const nonce = hexNonce();
    const expiresAt = utcSqlDate(Date.now() + 300000);
    try {
      const result = await env.ADS_DB.prepare(
        `INSERT INTO ads_love_evidence_reservations
         (id,claim_id,verifier_id,session_nonce,expires_at)
         SELECT ?,c.id,v.id,?,?
         FROM ads_impression_claims c CROSS JOIN ads_verifier_registry v
         WHERE c.id=? AND c.verification_status='pending'
           AND v.id=? AND v.status='active'
           AND NOT EXISTS (SELECT 1 FROM ads_verification_assessments a
                           WHERE a.claim_id=c.id AND a.verifier_id=v.id)
           AND NOT EXISTS (SELECT 1 FROM ads_love_verification_sessions s
                           WHERE s.claim_id=c.id AND s.verifier_id=v.id
                             AND s.status='issued' AND s.expires_at>CURRENT_TIMESTAMP)`
      ).bind(reservationId, nonce, expiresAt, input.claim_id.toLowerCase(), input.verifier_id).run();
      if (!Number.isInteger(result.meta?.changes) || result.meta.changes < 1) return reply({ error: 'reservation_unavailable' }, 409);
    } catch { return reply({ error: 'reservation_unavailable' }, 409); }
    return reply({ reservation_id: reservationId, claim_id: input.claim_id.toLowerCase(),
      verifier_id: input.verifier_id, session_nonce: nonce, expires_at: expiresAt + ' UTC',
      status: 'reserved', final_verification: false, billable: false }, 201);
  }

  const reservationId = finalize[1];
  if (!UUID.test(reservationId) || Object.keys(input).sort().join(',') !== 'envelope') {
    return reply({ error: 'invalid_finalization' }, 422);
  }
  const row = await env.ADS_DB.prepare(
    `SELECT r.id,r.claim_id,r.verifier_id,r.session_nonce,r.expires_at
     FROM ads_love_evidence_reservations r
     JOIN ads_impression_claims c ON c.id=r.claim_id
     JOIN ads_verifier_registry v ON v.id=r.verifier_id
     WHERE r.id=? AND r.status='reserved' AND r.expires_at>CURRENT_TIMESTAMP
       AND c.verification_status='pending' AND v.status='active'`
  ).bind(reservationId.toLowerCase()).first();
  if (!row) return reply({ error: 'finalization_unavailable' }, 409);

  const envelope = input.envelope;
  let digest;
  try { digest = await protectedEnvelopeDigest(envelope); }
  catch { return reply({ error: 'invalid_envelope' }, 422); }

  if (envelope.claim_id !== row.claim_id || envelope.verifier_id !== row.verifier_id ||
      envelope.session_nonce !== row.session_nonce ||
      Date.parse(envelope.expires_at) > Date.parse(row.expires_at + 'Z') ||
      Date.parse(envelope.issued_at) >= Date.parse(row.expires_at + 'Z')) {
    return reply({ error: 'envelope_binding_mismatch' }, 403);
  }
  try {
    // D1 triggers enforce reservation identity and atomic reservation finalization.
    const result = await env.ADS_DB.prepare(
      `INSERT INTO ads_love_verification_sessions
       (id,claim_id,verifier_id,session_nonce,envelope_digest,expires_at)
       SELECT r.id,r.claim_id,r.verifier_id,r.session_nonce,?,r.expires_at
       FROM ads_love_evidence_reservations r
       JOIN ads_impression_claims c ON c.id=r.claim_id
       JOIN ads_verifier_registry v ON v.id=r.verifier_id
       WHERE r.id=? AND r.status='reserved' AND r.expires_at>CURRENT_TIMESTAMP
         AND c.verification_status='pending' AND v.status='active'
         AND NOT EXISTS (SELECT 1 FROM ads_verification_assessments a
                         WHERE a.claim_id=r.claim_id AND a.verifier_id=r.verifier_id)`
    ).bind(digest, reservationId.toLowerCase()).run();
    if (!Number.isInteger(result.meta?.changes) || result.meta.changes < 1) return reply({ error: 'finalization_unavailable' }, 409);
  } catch { return reply({ error: 'finalization_unavailable' }, 409); }
  return reply({ session_id: reservationId.toLowerCase(), envelope_digest: digest,
    status: 'issued', reservation_status: 'finalized', final_verification: false, billable: false }, 201);
}
