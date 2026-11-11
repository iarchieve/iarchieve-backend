import { authenticatePublisher } from "./publisher-auth.mjs";
const respond = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const identities = [
  { key: "ADS_ADMIN_TOKEN", role: "admin", id: "dev-admin" },
  { key: "ADS_ADVERTISER_TOKEN", role: "advertiser", id: "adv-test-001" },
  { key: "ADS_PUBLISHER_TOKEN", role: "publisher", id: "pub-test-001", legacy: true }
];

async function authenticate(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = /^Bearer ([A-Fa-f0-9]{64})$/.exec(header);
  if (!match) return null;

  const encoder = new TextEncoder();
  const supplied = encoder.encode(match[1].toUpperCase());

  for (const identity of identities) {
    const secret = env[identity.key];
    if (!secret || !/^[A-Fa-f0-9]{64}$/.test(secret)) continue;

    const expected = encoder.encode(secret.toUpperCase());
    let difference = 0;
    for (let i = 0; i < expected.length; i++) {
      difference |= expected[i] ^ supplied[i];
    }
    if (difference === 0) {
      if (identity.legacy &&
          env.ADS_ALLOW_LEGACY_PUBLISHER_TOKEN !== "true") {
        return null;
      }
      return identity;
    }
  }

  return await authenticatePublisher(request, env);
}

async function readInput(request) {
  if (!(request.headers.get("Content-Type") || "")
      .toLowerCase().includes("application/json")) {
    return { error: "content_type_required" };
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).length > 16384) {
    return { error: "body_too_large" };
  }

  try {
    return { data: JSON.parse(body) };
  } catch {
    return { error: "invalid_json" };
  }
}

export async function handleAds(request, env) {
  const actor = await authenticate(request, env);
  if (!actor) return respond({ error: "unauthorized" }, 401);
  if (!env.ADS_DB) return respond({ error: "database_unavailable" }, 503);

  const path = new URL(request.url).pathname;
  const campaigns = path === "/api/ads/campaigns";
  const placements = path === "/api/ads/placements";

  if (!campaigns && !placements) {
    return respond({ error: "not_found" }, 404);
  }

  const requiredRole = campaigns ? "advertiser" : "publisher";

  if (actor.role !== "admin" && actor.role !== requiredRole) {
    return respond({ error: "forbidden" }, 403);
  }

  const table = campaigns ? "ads_campaigns" : "ads_placements";
  const ownerField = campaigns ? "advertiser_id" : "publisher_id";

  if (request.method === "GET") {
    const sql = actor.role === "admin"
      ? `SELECT * FROM ${table} ORDER BY created_at DESC LIMIT 100`
      : `SELECT * FROM ${table} WHERE ${ownerField}=? ORDER BY created_at DESC LIMIT 100`;

    const stmt = env.ADS_DB.prepare(sql);
    const result = await (
      actor.role === "admin" ? stmt.all() : stmt.bind(actor.id).all()
    );
    return respond({ items: result.results });
  }

  if (request.method !== "POST") {
    return respond({ error: "method_not_allowed" }, 405);
  }

  const input = await readInput(request);
  if (input.error) return respond({ error: input.error }, 400);

  const data = input.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return respond({ error: "invalid_input" }, 422);
  }

  const ownerId = data[ownerField];

  if (
    typeof ownerId !== "string" ||
    (actor.role !== "admin" && ownerId !== actor.id) ||
    typeof data.name !== "string" ||
    !data.name.trim() ||
    data.name.length > 100
  ) {
    return respond({ error: "invalid_owner_or_name" }, 422);
  }

  if (campaigns) {
    if (
      !["display", "video", "native"].includes(data.format) ||
      !Number.isSafeInteger(data.daily_budget_krw) ||
      data.daily_budget_krw <= 0
    ) return respond({ error: "invalid_campaign" }, 422);
  } else {
    if (
      !Number.isSafeInteger(data.floor_cpm_krw) ||
      data.floor_cpm_krw < 0 || (data.format !== undefined && !["display", "video", "native"].includes(data.format))
    ) return respond({ error: "invalid_placement" }, 422);
  }

  const owner = await env.ADS_DB.prepare(
    "SELECT id FROM ads_accounts WHERE id=? AND role=? AND status='active'"
  ).bind(ownerId, requiredRole).first();

  if (!owner) return respond({ error: "invalid_owner" }, 422);

  const id = crypto.randomUUID();

  const insert = campaigns
    ? env.ADS_DB.prepare(
        "INSERT INTO ads_campaigns (id,advertiser_id,name,format,daily_budget_krw) VALUES (?,?,?,?,?)"
      ).bind(id, ownerId, data.name.trim(), data.format, data.daily_budget_krw)
    : env.ADS_DB.prepare(
        "INSERT INTO ads_placements (id,publisher_id,name,floor_cpm_krw,format) VALUES (?,?,?,?,?)"
      ).bind(id, ownerId, data.name.trim(), data.floor_cpm_krw, data.format ?? "display");

  const audit = env.ADS_DB.prepare(
    "INSERT INTO ads_audit_log (id,actor_id,action,target_type,target_id) VALUES (?,?,?,?,?)"
  ).bind(
    crypto.randomUUID(),
    actor.id,
    "create",
    campaigns ? "campaign" : "placement",
    id
  );

  await env.ADS_DB.batch([insert, audit]);

  return respond({
    id,
    status: campaigns ? "draft" : "pending"
  }, 201);
}
