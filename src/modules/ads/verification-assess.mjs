const json = (value, status = 200) => Response.json(value, {
  status,
  headers: { "Cache-Control": "no-store" }
});

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const digest = /^[0-9a-f]{64}$/;
const verifierPattern = /^[a-zA-Z0-9_-]{1,128}$/;
const signaturePattern = /^[A-Za-z0-9_-]{86}$/;
const encoder = new TextEncoder();

function decodeSignature(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "==");
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function canonical(data) {
  return [
    "iarchieve.ads.assessment.v1",
    data.claim_id.toLowerCase(),
    data.verifier_id,
    data.verdict,
    data.evidence_digest
  ].join("\n");
}

async function sha256(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

export async function handleVerificationAssessment(request, env) {
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405);
  }

  if (!env.ADS_DB) {
    return json({ error: "database_unavailable" }, 503);
  }

  if (!/^application\/json(?:\s*;|$)/i.test(
    request.headers.get("Content-Type") || ""
  )) {
    return json({ error: "content_type_required" }, 400);
  }

  let input;
  try {
    const length = request.headers.get("Content-Length");
    if (length !== null && Number(length) > 4096) {
      return json({ error: "body_too_large" }, 413);
    }

    const body = await request.text();
    if (encoder.encode(body).length > 4096) {
      return json({ error: "body_too_large" }, 413);
    }
    input = JSON.parse(body);
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).sort().join(",") !==
      "claim_id,evidence_digest,signature,verdict,verifier_id" ||
    typeof input.claim_id !== "string" ||
    typeof input.verifier_id !== "string" ||
    typeof input.verdict !== "string" ||
    typeof input.evidence_digest !== "string" ||
    typeof input.signature !== "string" ||
    !uuid.test(input.claim_id) ||
    !verifierPattern.test(input.verifier_id) ||
    !["accepted", "rejected", "inconclusive"].includes(input.verdict) ||
    !digest.test(input.evidence_digest) ||
    !signaturePattern.test(input.signature)
  ) {
    return json({ error: "invalid_assessment" }, 422);
  }

  const verifier = await env.ADS_DB.prepare(
    `SELECT public_key_jwk FROM ads_verifier_registry
     WHERE id=? AND status='active'`
  ).bind(input.verifier_id).first();

  if (!verifier) {
    return json({ error: "verifier_not_authorized" }, 403);
  }

  let valid = false;
  try {
    const jwk = JSON.parse(verifier.public_key_jwk);
    if (
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      !/^[A-Za-z0-9_-]{43}$/.test(jwk.x || "") ||
      !/^[A-Za-z0-9_-]{43}$/.test(jwk.y || "") ||
      Object.hasOwn(jwk, "d")
    ) {
      return json({ error: "verifier_key_invalid" }, 503);
    }

    const key = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x: jwk.x,
        y: jwk.y,
        ext: true
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );

    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      decodeSignature(input.signature),
      encoder.encode(canonical(input))
    );
  } catch {
    return json({ error: "invalid_signature" }, 403);
  }

  if (!valid) {
    return json({ error: "invalid_signature" }, 403);
  }

  const assessmentDigest = await sha256(
    encoder.encode(canonical(input))
  );

  const assessmentId = crypto.randomUUID();

  // Both registry status and claim status are rechecked at INSERT time.
  // An assessment never changes the claim's final status or billing.
  const result = await env.ADS_DB.prepare(
    `INSERT OR IGNORE INTO ads_verification_assessments
     (id,claim_id,verifier_id,verdict,
      evidence_digest,assessment_digest)
     SELECT ?,c.id,?,?,?,?
     FROM ads_impression_claims c
     JOIN ads_verifier_registry v ON v.id=?
     WHERE c.id=?
       AND c.verification_status='pending'
       AND v.status='active'`
  ).bind(
    assessmentId,
    input.verifier_id,
    input.verdict,
    input.evidence_digest,
    assessmentDigest,
    input.verifier_id,
    input.claim_id
  ).run();

  if (result.meta?.changes !== 1) {
    return json({ error: "duplicate_or_unavailable_claim" }, 409);
  }

  return json({
    assessment_id: assessmentId,
    claim_id: input.claim_id,
    verifier_id: input.verifier_id,
    assessment_recorded: true,
    final_verification: false,
    billable: false
  }, 201);
}