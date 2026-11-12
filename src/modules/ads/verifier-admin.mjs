const encoder = new TextEncoder();
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HEX64 = /^[a-fA-F0-9]{64}$/;
const B64URL43 = /^[A-Za-z0-9_-]{43}$/;
const root = '/api/ads/admin/verifiers';

function reply(value, status = 200) {
  return Response.json(value, { status, headers: { 'Cache-Control': 'no-store' } });
}
function adminAuthorized(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(request.headers.get('Authorization') || '');
  const expected = env.ADS_ADMIN_TOKEN;
  if (!match || typeof expected !== 'string' || !HEX64.test(expected)) return false;
  const supplied = match[1].toLowerCase();
  const secret = expected.toLowerCase();
  let different = 0;
  for (let i = 0; i < 64; i++) different |= supplied.charCodeAt(i) ^ secret.charCodeAt(i);
  return different === 0;
}
async function parseBody(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || '')) {
    return { error: 'content_type_required', status: 400 };
  }
  const length = request.headers.get('Content-Length');
  if (length !== null && (!Number.isSafeInteger(Number(length)) || Number(length) < 0 || Number(length) > 2048)) {
    return { error: 'body_too_large', status: 413 };
  }
  try {
    const reader = request.body?.getReader();
    if (!reader) return { error: 'invalid_json', status: 400 };
    const parts = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 2048) {
        await reader.cancel();
        return { error: 'body_too_large', status: 413 };
      }
      parts.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const item of parts) { bytes.set(item, offset); offset += item.byteLength; }
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { error: 'invalid_json', status: 400 };
    }
    return { data: parsed };
  } catch { return { error: 'invalid_json', status: 400 }; }
}
function canonicalPublicKey(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      Object.keys(raw).sort().join(',') !== 'crv,kty,x,y' ||
      raw.kty !== 'EC' || raw.crv !== 'P-256' ||
      typeof raw.x !== 'string' || !B64URL43.test(raw.x) ||
      typeof raw.y !== 'string' || !B64URL43.test(raw.y)) return null;
  return { kty: 'EC', crv: 'P-256', x: raw.x, y: raw.y };
}
export async function handleVerifierAdmin(request, env) {
  if (!adminAuthorized(request, env)) return reply({ error: 'unauthorized' }, 401);
  if (!env.ADS_DB) return reply({ error: 'database_unavailable' }, 503);
  const pathname = new URL(request.url).pathname;
  const revokeMatch = /^\/api\/ads\/admin\/verifiers\/([^/]+)\/revoke$/.exec(pathname);
  if (pathname !== root && !revokeMatch) return reply({ error: 'not_found' }, 404);
  if (pathname === root && request.method === 'GET') {
    const result = await env.ADS_DB.prepare(
      'SELECT id,status,created_at FROM ads_verifier_registry ORDER BY created_at DESC,id DESC LIMIT 100'
    ).all();
    return reply({ items: result.results, billable: false });
  }
  if (request.method !== 'POST') return reply({ error: 'method_not_allowed' }, 405);
  const parsed = await parseBody(request);
  if (parsed.error) return reply({ error: parsed.error }, parsed.status);
  if (revokeMatch) {
    const id = revokeMatch[1];
    if (!ID.test(id) || Object.keys(parsed.data).length !== 0) return reply({ error: 'invalid_revocation' }, 422);
    try {
      const result = await env.ADS_DB.prepare(
        "UPDATE ads_verifier_registry SET status='revoked' WHERE id=? AND status='active'"
      ).bind(id).run();
      if (result.meta?.changes !== 1) return reply({ error: 'verifier_not_active' }, 409);
    } catch { return reply({ error: 'verifier_not_active' }, 409); }
    return reply({ verifier_id: id, status: 'revoked', billable: false });
  }
  const input = parsed.data;
  if (Object.keys(input).sort().join(',') !== 'public_key_jwk,verifier_id' ||
      typeof input.verifier_id !== 'string' || !ID.test(input.verifier_id)) {
    return reply({ error: 'invalid_verifier_registration' }, 422);
  }
  const jwk = canonicalPublicKey(input.public_key_jwk);
  if (!jwk) return reply({ error: 'invalid_public_key' }, 422);
  try {
    // Import validates that x/y describe a valid point on the P-256 curve.
    await crypto.subtle.importKey('jwk', { ...jwk, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch { return reply({ error: 'invalid_public_key' }, 422); }
  try {
    const result = await env.ADS_DB.prepare(
      "INSERT INTO ads_verifier_registry(id,public_key_jwk,status) VALUES (?,?,'active')"
    ).bind(input.verifier_id, JSON.stringify(jwk)).run();
    if (result.meta?.changes !== 1) return reply({ error: 'verifier_conflict' }, 409);
  } catch { return reply({ error: 'verifier_conflict' }, 409); }
  return reply({ verifier_id: input.verifier_id, status: 'active', billable: false }, 201);
}
