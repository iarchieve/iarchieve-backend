const encoder = new TextEncoder();

const respond = (body, status = 200) =>
  Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9_-]{1,128}$/;

function isAdmin(request, env) {
  const supplied = /^Bearer ([a-fA-F0-9]{64})$/.exec(
    request.headers.get("Authorization") || ""
  );

  const expected = env.ADS_ADMIN_TOKEN;

  if (!supplied ||
      typeof expected !== "string" ||
      !HEX64.test(expected.toLowerCase())) {
    return false;
  }

  let difference = 0;
  const actual = supplied[1].toLowerCase();
  const secret = expected.toLowerCase();

  for (let i = 0; i < 64; i++) {
    difference |= actual.charCodeAt(i) ^ secret.charCodeAt(i);
  }

  return difference === 0;
}

function hexNonce() {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(16)),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

export async function handleLoveSessionIssue(request, env) {
  if (request.method !== "POST") {
    return respond({ error: "method_not_allowed" }, 405);
  }

  if (!isAdmin(request, env)) {
    return respond({ error: "unauthorized" }, 401);
  }

  if (!env.ADS_DB) {
    return respond({ error: "database_unavailable" }, 503);
  }

  if (!/^application\/json(?:\s*;|$)/i.test(
    request.headers.get("Content-Type") || ""
  )) {
    return respond({ error: "content_type_required" }, 400);
  }

  let data;
  try {
    const size = request.headers.get("Content-Length");
    if (size !== null && Number(size) > 2048) {
      return respond({ error: "body_too_large" }, 413);
    }

    const body = await request.text();
    if (encoder.encode(body).length > 2048) {
      return respond({ error: "body_too_large" }, 413);
    }

    data = JSON.parse(body);
  } catch {
    return respond({ error: "invalid_json" }, 400);
  }

  if (!data || typeof data !== "object" ||
      Array.isArray(data) ||
      Object.keys(data).sort().join(",") !==
        "claim_id,envelope_digest,verifier_id" ||
      typeof data.claim_id !== "string" ||
      typeof data.verifier_id !== "string" ||
      typeof data.envelope_digest !== "string" ||
      !UUID.test(data.claim_id) ||
      !ID.test(data.verifier_id) ||
      !HEX64.test(data.envelope_digest)) {
    return respond({ error: "invalid_session_request" }, 422);
  }

  const sessionId = crypto.randomUUID();
  const nonce = hexNonce();
  const expiresAt = new Date(Date.now() + 300000)
    .toISOString().replace("T", " ").slice(0, 19);

  // Single-statement conditional issuance.
  // Only pending claims and active registered verifiers qualify.
  // Prevents parallel outstanding sessions for a claim/verifier pair.
  const result = await env.ADS_DB.prepare(
    `INSERT INTO ads_love_verification_sessions
     (id,claim_id,verifier_id,session_nonce,envelope_digest,expires_at)
     SELECT ?,c.id,v.id,?,?,?
     FROM ads_impression_claims c
     CROSS JOIN ads_verifier_registry v
     WHERE c.id=?
       AND c.verification_status='pending'
       AND v.id=?
       AND v.status='active'
       AND NOT EXISTS (
         SELECT 1 FROM ads_love_verification_sessions s
         WHERE s.claim_id=c.id AND s.verifier_id=v.id
           AND s.status='issued'
           AND s.expires_at>CURRENT_TIMESTAMP
       )
       AND NOT EXISTS (
         SELECT 1 FROM ads_verification_assessments a
         WHERE a.claim_id=c.id AND a.verifier_id=v.id
       )`
  ).bind(
    sessionId,
    nonce,
    data.envelope_digest,
    expiresAt,
    data.claim_id.toLowerCase(),
    data.verifier_id
  ).run();

  if (result.meta?.changes !== 1) {
    return respond({ error: "session_not_issuable" }, 409);
  }

  return respond({
    session_id: sessionId,
    claim_id: data.claim_id.toLowerCase(),
    verifier_id: data.verifier_id,
    session_nonce: nonce,
    envelope_digest: data.envelope_digest,
    expires_at: expiresAt + " UTC",
    status: "issued",
    final_verification: false,
    billable: false
  }, 201);
}