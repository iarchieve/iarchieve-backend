const encoder = new TextEncoder();

const reply = (data, status = 200) => Response.json(data, {
  status,
  headers: { "Cache-Control": "no-store" }
});

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const VERIFIER = /^[A-Za-z0-9_-]{1,128}$/;
const BASE64URL = /^[A-Za-z0-9_-]{86}$/;

export function canonicalLoveAssessment(value) {
  return [
    "iarchieve.ads.love-assessment.v1",
    value.claim_id.toLowerCase(),
    value.verifier_id,
    value.session_id,
    value.session_nonce,
    value.envelope_digest,
    value.verdict,
    value.evidence_digest
  ].join("\n");
}

function signatureBytes(value) {
  const text = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(text + "==");

  const bytes = Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );

  if (bytes.length !== 64) {
    throw new Error("invalid_signature_size");
  }

  return bytes;
}

async function digestHex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

export async function handleLoveAssessment(request, env) {
  if (request.method !== "POST") {
    return reply({ error: "method_not_allowed" }, 405);
  }

  if (!env.ADS_DB) {
    return reply({ error: "database_unavailable" }, 503);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    return reply({ error: "content_type_required" }, 400);
  }

  let input;

  try {
    const declared = request.headers.get("Content-Length");

    if (declared !== null && Number(declared) > 4096) {
      return reply({ error: "body_too_large" }, 413);
    }

    const body = await request.text();

    if (encoder.encode(body).length > 4096) {
      return reply({ error: "body_too_large" }, 413);
    }

    input = JSON.parse(body);
  } catch {
    return reply({ error: "invalid_json" }, 400);
  }

  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).sort().join(",") !==
      "claim_id,envelope_digest,evidence_digest,session_id,session_nonce,signature,verdict,verifier_id" ||
    typeof input.claim_id !== "string" ||
    typeof input.verifier_id !== "string" ||
    typeof input.session_id !== "string" ||
    typeof input.session_nonce !== "string" ||
    typeof input.envelope_digest !== "string" ||
    typeof input.verdict !== "string" ||
    typeof input.evidence_digest !== "string" ||
    typeof input.signature !== "string" ||
    !UUID.test(input.claim_id) ||
    !VERIFIER.test(input.verifier_id) ||
    !UUID.test(input.session_id) ||
    !HEX32.test(input.session_nonce) ||
    !HEX64.test(input.envelope_digest) ||
    !HEX64.test(input.evidence_digest) ||
    !["accepted", "rejected", "inconclusive"].includes(input.verdict) ||
    !BASE64URL.test(input.signature)
  ) {
    return reply({ error: "invalid_love_assessment" }, 422);
  }

  // Session identity and expiry are checked against D1's clock.
  const session = await env.ADS_DB.prepare(
    `SELECT s.id,s.session_nonce,s.envelope_digest,
            v.public_key_jwk
     FROM ads_love_verification_sessions s
     JOIN ads_verifier_registry v
       ON v.id=s.verifier_id
     JOIN ads_impression_claims c
       ON c.id=s.claim_id
     WHERE s.id=?
       AND s.claim_id=?
       AND s.verifier_id=?
       AND s.status='issued'
       AND s.expires_at>CURRENT_TIMESTAMP
       AND v.status='active'
       AND c.verification_status='pending'`
  ).bind(
    input.session_id,
    input.claim_id.toLowerCase(),
    input.verifier_id
  ).first();

  if (!session) {
    return reply({ error: "session_not_available" }, 409);
  }

  if (
    session.session_nonce !== input.session_nonce ||
    session.envelope_digest !== input.envelope_digest
  ) {
    return reply({ error: "love_binding_mismatch" }, 403);
  }

  let verified = false;

  try {
    const stored = JSON.parse(session.public_key_jwk);

    if (
      stored.kty !== "EC" ||
      stored.crv !== "P-256" ||
      !/^[A-Za-z0-9_-]{43}$/.test(stored.x || "") ||
      !/^[A-Za-z0-9_-]{43}$/.test(stored.y || "") ||
      Object.hasOwn(stored, "d")
    ) {
      return reply({ error: "invalid_verifier_key" }, 503);
    }

    const key = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x: stored.x,
        y: stored.y,
        ext: true
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      signatureBytes(input.signature),
      encoder.encode(canonicalLoveAssessment(input))
    );
  } catch {
    return reply({ error: "invalid_signature" }, 403);
  }

  if (!verified) {
    return reply({ error: "invalid_signature" }, 403);
  }

  const assessmentDigest = await digestHex(
    canonicalLoveAssessment(input)
  );

  const assessmentId = crypto.randomUUID();

  // INSERT and session consumption are atomic through migration 0009.
  // Do not use INSERT OR IGNORE here: it could conceal constraint errors.
  try {
    const result = await env.ADS_DB.prepare(
      `INSERT INTO ads_verification_assessments
       (id,claim_id,verifier_id,verdict,
        evidence_digest,assessment_digest,love_session_id)
       SELECT ?,c.id,?,?,?,?,s.id
       FROM ads_love_verification_sessions s
       JOIN ads_impression_claims c ON c.id=s.claim_id
       JOIN ads_verifier_registry v ON v.id=s.verifier_id
       WHERE s.id=?
         AND s.claim_id=?
         AND s.verifier_id=?
         AND s.session_nonce=?
         AND s.envelope_digest=?
         AND s.status='issued'
         AND s.expires_at>CURRENT_TIMESTAMP
         AND v.status='active'
         AND c.verification_status='pending'`
    ).bind(
      assessmentId,
      input.verifier_id,
      input.verdict,
      input.evidence_digest,
      assessmentDigest,
      input.session_id,
      input.claim_id.toLowerCase(),
      input.verifier_id,
      input.session_nonce,
      input.envelope_digest
    ).run();

    if (!Number.isInteger(result.meta?.changes) || result.meta.changes < 1) {
      return reply({ error: "session_not_available" }, 409);
    }
  } catch {
    // Includes duplicate verifier assessments and consumed sessions.
    // No database details are disclosed to clients.
    return reply({ error: "assessment_conflict" }, 409);
  }

  return reply({
    assessment_id: assessmentId,
    session_id: input.session_id,
    claim_id: input.claim_id.toLowerCase(),
    verifier_id: input.verifier_id,
    signature_verified: true,
    session_consumed: true,
    final_verification: false,
    billable: false
  }, 201);
}