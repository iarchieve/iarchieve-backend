import { authenticatePublisher } from "./publisher-auth.mjs";

const reply = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

export async function handleAdsDeliveryIssue(request, env) {
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
  if (!type.toLowerCase().includes("application/json")) {
    return reply({ error: "content_type_required" }, 400);
  }

  let input;

  try {
    if (Number(request.headers.get("Content-Length")) > 2048) {
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

  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some(k => k !== "placement_id") ||
    typeof input.placement_id !== "string" ||
    !/^[a-zA-Z0-9_-]{1,128}$/.test(input.placement_id)
  ) {
    return reply({ error: "invalid_placement_id" }, 422);
  }

  const placement = await env.ADS_DB.prepare(
    `SELECT p.id,p.format
     FROM ads_placements p
     JOIN ads_accounts a ON a.id=p.publisher_id
     WHERE p.id=? AND p.publisher_id=?
       AND p.status='approved'
       AND a.role='publisher' AND a.status='active'`
  ).bind(input.placement_id, actor.id).first();

  if (!placement) {
    return reply({ error: "placement_not_available" }, 404);
  }

  const ad = await env.ADS_DB.prepare(
    `SELECT c.id AS campaign_id,c.name,c.format,
            r.id AS creative_id,r.title,
            r.image_url,r.target_url
     FROM ads_campaigns c
     JOIN ads_accounts a ON a.id=c.advertiser_id
     JOIN ads_creatives r ON r.campaign_id=c.id
     WHERE c.status='active' AND a.status='active'
       AND a.role='advertiser'
       AND r.status='approved' AND c.format=?
     ORDER BY c.created_at,c.id,r.created_at,r.id
     LIMIT 1`
  ).bind(placement.format).first();

  if (!ad) {
    return reply({ item: null, billable: false });
  }

  const id = crypto.randomUUID();
  const issued = new Date();
  const expires = new Date(issued.getTime() + 300000);
  const expiresAt = expires.toISOString()
    .replace("T", " ").slice(0, 19);

  await env.ADS_DB.prepare(
    `INSERT INTO ads_delivery_requests
     (id,campaign_id,creative_id,placement_id,expires_at)
     VALUES (?,?,?,?,?)`
  ).bind(
    id,ad.campaign_id,ad.creative_id,
    placement.id,expiresAt
  ).run();

  return reply({
    delivery_request_id: id,
    expires_at: expiresAt + " UTC",
    item: {
      campaign_id: ad.campaign_id,
      creative_id: ad.creative_id,
      placement_id: placement.id,
      name: ad.name,
      format: ad.format,
      title: ad.title,
      image_url: ad.image_url,
      target_url: ad.target_url
    },
    billable: false,
    verification_status: "not_submitted"
  }, 201);
}