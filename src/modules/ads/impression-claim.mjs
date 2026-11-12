import { authenticatePublisher } from "./publisher-auth.mjs";

const reply = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[0-9a-f]{64}$/i;

export async function handleImpressionClaim(request, env) {
  if (request.method !== "POST") {
    return reply({ error: "method_not_allowed" }, 405);
  }

  if (!env.ADS_DB) {
    return reply({ error: "database_unavailable" }, 503);
  }

  const actor = await authenticatePublisher(request, env);
  if (!actor) {
    return reply({ error: "unauthorized" }, 401);
  }

  const type = request.headers.get("Content-Type") || "";
  if (!/^application\/json(?:\s*;|$)/i.test(type)) {
    return reply({ error: "content_type_required" }, 400);
  }

  let input;

  try {
    const declared = request.headers.get("Content-Length");
    if (declared !== null && Number(declared) > 2048) {
      return reply({ error: "body_too_large" }, 413);
    }

    const body = await request.text();
    if (new TextEncoder().encode(body).length > 2048) {
      return reply({ error: "body_too_large" }, 413);
    }

    input = JSON.parse(body);
  } catch {
    return reply({ error: "invalid_json" }, 400);
  }

  if (!input || typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).length !== 2 ||
      !Object.hasOwn(input, "delivery_request_id") ||
      !Object.hasOwn(input, "proof_digest") ||
      typeof input.delivery_request_id !== "string" ||
      typeof input.proof_digest !== "string" ||
      !UUID.test(input.delivery_request_id) ||
      !DIGEST.test(input.proof_digest)) {
    return reply({ error: "invalid_claim" }, 422);
  }

  // The requesting publisher must own the issued placement.
  // Expiration is checked by D1's clock, not by client time.
  const issuance = await env.ADS_DB.prepare(
    `SELECT d.id
     FROM ads_delivery_requests d
     JOIN ads_placements p ON p.id=d.placement_id
     JOIN ads_accounts a ON a.id=p.publisher_id
     WHERE d.id=?
       AND p.publisher_id=?
       AND a.role='publisher'
       AND a.status='active'
       AND d.status='issued'
       AND d.expires_at > CURRENT_TIMESTAMP`
  ).bind(input.delivery_request_id, actor.id).first();

  if (!issuance) {
    return reply({ error: "delivery_not_available" }, 404);
  }

  const claimId = crypto.randomUUID();

  // INSERT OR IGNORE and UNIQUE(delivery_request_id)
  // prevent concurrent duplicate submissions.
  const result = await env.ADS_DB.prepare(
    `INSERT OR IGNORE INTO ads_impression_claims
     (id,delivery_request_id,proof_digest)
     SELECT ?,d.id,?
     FROM ads_delivery_requests d
     JOIN ads_placements p ON p.id=d.placement_id
     JOIN ads_accounts a ON a.id=p.publisher_id
     WHERE d.id=?
       AND p.publisher_id=?
       AND a.role='publisher'
       AND a.status='active'
       AND d.status='issued'
       AND d.expires_at > CURRENT_TIMESTAMP`
  ).bind(
    claimId,
    input.proof_digest.toLowerCase(),
    input.delivery_request_id,
    actor.id
  ).run();

  if (result.meta?.changes !== 1) {
    return reply({ error: "duplicate_or_expired_claim" }, 409);
  }

  return reply({
    claim_id: claimId,
    delivery_request_id: input.delivery_request_id,
    verification_status: "pending",
    billable: false
  }, 202);
}