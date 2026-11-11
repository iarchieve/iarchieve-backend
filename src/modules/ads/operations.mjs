const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const tokens = [
  ["ADS_ADMIN_TOKEN", "admin", "dev-admin"],
  ["ADS_ADVERTISER_TOKEN", "advertiser", "adv-test-001"],
  ["ADS_PUBLISHER_TOKEN", "publisher", "pub-test-001"]
];

function authenticate(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(
    request.headers.get("Authorization") || ""
  );
  if (!match) return null;

  const supplied = match[1].toUpperCase();

  for (const [key, role, id] of tokens) {
    const secret = env[key];
    if (typeof secret !== "string" ||
        !/^[a-fA-F0-9]{64}$/.test(secret)) continue;

    const expected = secret.toUpperCase();
    let difference = 0;

    for (let i = 0; i < 64; i++) {
      difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
    }

    if (difference === 0) return { role, id };
  }
  return null;
}

async function readJson(request) {
  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().includes("application/json")) {
    return { error: "content_type_required" };
  }

  const limit = 16384;
  const length = request.headers.get("Content-Length");

  if (length && Number(length) > limit) {
    return { error: "body_too_large" };
  }

  const reader = request.body?.getReader();
  if (!reader) return { error: "invalid_json" };

  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        return { error: "body_too_large" };
      }
      chunks.push(value);
    }

    const bytes = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    return { data: JSON.parse(new TextDecoder().decode(bytes)) };
  } catch {
    return { error: "invalid_json" };
  }
}

export async function handleAdsOperations(request, env) {
  const actor = authenticate(request, env);
  if (!actor) return json({ error: "unauthorized" }, 401);
  if (!env.ADS_DB) return json({ error: "database_unavailable" }, 503);

  const path = new URL(request.url).pathname;

  if (path === "/api/ads/audit") {
    if (actor.role !== "admin") {
      return json({ error: "forbidden" }, 403);
    }
    if (request.method !== "GET") {
      return json({ error: "method_not_allowed" }, 405);
    }

    const result = await env.ADS_DB.prepare(
      "SELECT * FROM ads_audit_log ORDER BY created_at DESC LIMIT 100"
    ).all();

    return json({ items: result.results });
  }

  const campaign = /^\/api\/ads\/campaigns\/([^/]+)$/.exec(path);
  const placement = /^\/api\/ads\/placements\/([^/]+)$/.exec(path);

  if (!campaign && !placement) {
    return json({ error: "not_found" }, 404);
  }

  if (request.method !== "PATCH") {
    return json({ error: "method_not_allowed" }, 405);
  }

  const isCampaign = Boolean(campaign);
  const id = decodeURIComponent((campaign || placement)[1]);

  if (id.length > 128 || !id) {
    return json({ error: "invalid_id" }, 422);
  }

  if (isCampaign) {
    if (!["admin", "advertiser"].includes(actor.role)) {
      return json({ error: "forbidden" }, 403);
    }
  } else if (actor.role !== "admin") {
    return json({ error: "forbidden" }, 403);
  }

  const input = await readJson(request);
  if (input.error) return json({ error: input.error }, 400);

  const data = input.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return json({ error: "invalid_input" }, 422);
  }

  const allowed = isCampaign
    ? ["draft", "active", "paused", "archived"]
    : ["pending", "approved", "rejected", "paused"];

  if (!allowed.includes(data.status) ||
      Object.keys(data).some(key => key !== "status")) {
    return json({ error: "invalid_status" }, 422);
  }

  const table = isCampaign ? "ads_campaigns" : "ads_placements";
  const record = await env.ADS_DB.prepare(
    `SELECT * FROM ${table} WHERE id=?`
  ).bind(id).first();

  if (!record) return json({ error: "not_found" }, 404);

  if (isCampaign &&
      actor.role === "advertiser" &&
      record.advertiser_id !== actor.id) {
    return json({ error: "forbidden" }, 403);
  }

  const transitions = isCampaign
    ? {
        draft: ["active", "archived"],
        active: ["paused", "archived"],
        paused: ["active", "archived"],
        archived: []
      }
    : {
        pending: ["approved", "rejected"],
        approved: ["paused", "rejected"],
        paused: ["approved", "rejected"],
        rejected: []
      };

  if (!transitions[record.status]?.includes(data.status)) {
    return json({ error: "invalid_transition" }, 409);
  }

  const targetType = isCampaign ? "campaign" : "placement";

  const update = env.ADS_DB.prepare(
    `UPDATE ${table} SET status=? WHERE id=? AND status=?`
  ).bind(data.status, id, record.status);

  const audit = env.ADS_DB.prepare(
    "INSERT INTO ads_audit_log (id,actor_id,action,target_type,target_id) VALUES (?,?,?,?,?)"
  ).bind(
    crypto.randomUUID(),
    actor.id,
    `status:${record.status}->${data.status}`,
    targetType,
    id
  );

  const results = await env.ADS_DB.batch([update, audit]);

  if (results[0]?.meta?.changes !== 1) {
    return json({ error: "concurrent_update" }, 409);
  }

  return json({
    id,
    previous_status: record.status,
    status: data.status
  });
}
