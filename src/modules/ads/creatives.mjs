const reply = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

function identity(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(
    request.headers.get("Authorization") || ""
  );
  if (!match) return null;

  const identities = [
    ["ADS_ADMIN_TOKEN", "admin", "dev-admin"],
    ["ADS_ADVERTISER_TOKEN", "advertiser", "adv-test-001"]
  ];

  for (const [key, role, id] of identities) {
    const secret = env[key];
    if (typeof secret !== "string" ||
        !/^[a-fA-F0-9]{64}$/.test(secret)) continue;

    let difference = 0;
    const a = match[1].toUpperCase();
    const b = secret.toUpperCase();
    for (let i = 0; i < 64; i++) {
      difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    if (difference === 0) return { role, id };
  }
  return null;
}

function validUrl(value) {
  if (typeof value !== "string" || value.length > 2048)
    return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" &&
      Boolean(url.hostname) &&
      !url.username && !url.password;
  } catch {
    return false;
  }
}

export async function handleAdsCreatives(request, env) {
  const actor = identity(request, env);
  if (!actor) return reply({ error: "unauthorized" }, 401);
  if (!env.ADS_DB)
    return reply({ error: "database_unavailable" }, 503);

  const path = new URL(request.url).pathname;
  const detail = /^\/api\/ads\/creatives\/([^/]+)$/.exec(path);

  if (path === "/api/ads/creatives") {
    if (request.method === "GET") {
      const query = actor.role === "admin"
        ? "SELECT * FROM ads_creatives ORDER BY created_at DESC LIMIT 100"
        : `SELECT c.* FROM ads_creatives c
           JOIN ads_campaigns a ON a.id=c.campaign_id
           WHERE a.advertiser_id=?
           ORDER BY c.created_at DESC LIMIT 100`;

      const stmt = env.ADS_DB.prepare(query);
      const result = actor.role === "admin"
        ? await stmt.all()
        : await stmt.bind(actor.id).all();

      return reply({ items: result.results });
    }

    if (request.method !== "POST")
      return reply({ error: "method_not_allowed" }, 405);

    let data;
    try {
      const body = await request.text();
      if (new TextEncoder().encode(body).length > 16384)
        return reply({ error: "body_too_large" }, 413);
      data = JSON.parse(body);
    } catch {
      return reply({ error: "invalid_json" }, 400);
    }

    if (!data || typeof data !== "object" ||
        Array.isArray(data) ||
        typeof data.campaign_id !== "string" ||
        data.campaign_id.length > 128 ||
        !data.campaign_id ||
        typeof data.title !== "string" ||
        !data.title.trim() ||
        data.title.length > 120 ||
        !validUrl(data.image_url) ||
        !validUrl(data.target_url)) {
      return reply({ error: "invalid_creative" }, 422);
    }

    const campaign = await env.ADS_DB.prepare(
      "SELECT advertiser_id FROM ads_campaigns WHERE id=?"
    ).bind(data.campaign_id).first();

    if (!campaign)
      return reply({ error: "campaign_not_found" }, 404);

    if (actor.role !== "admin" &&
        campaign.advertiser_id !== actor.id)
      return reply({ error: "forbidden" }, 403);

    const id = crypto.randomUUID();

    await env.ADS_DB.batch([
      env.ADS_DB.prepare(
        `INSERT INTO ads_creatives
         (id,campaign_id,title,image_url,target_url)
         VALUES (?,?,?,?,?)`
      ).bind(
        id, data.campaign_id, data.title.trim(),
        data.image_url, data.target_url
      ),
      env.ADS_DB.prepare(
        `INSERT INTO ads_audit_log
         (id,actor_id,action,target_type,target_id)
         VALUES (?,?,?,?,?)`
      ).bind(
        crypto.randomUUID(), actor.id,
        "create", "creative", id
      )
    ]);

    return reply({ id, status: "pending" }, 201);
  }

  if (detail && request.method === "PATCH") {
    if (actor.role !== "admin")
      return reply({ error: "forbidden" }, 403);

    const id = detail[1];
    if (id.length > 128)
      return reply({ error: "invalid_id" }, 422);

    let data;
    try {
      data = await request.json();
    } catch {
      return reply({ error: "invalid_json" }, 400);
    }

    if (!data || typeof data !== "object" ||
        Array.isArray(data) ||
        !["approved","rejected"].includes(data.status) ||
        Object.keys(data).some(k => k !== "status")) {
      return reply({ error: "invalid_status" }, 422);
    }

    const results = await env.ADS_DB.batch([
      env.ADS_DB.prepare(
        `UPDATE ads_creatives SET status=?
         WHERE id=? AND status='pending'`
      ).bind(data.status,id),
      env.ADS_DB.prepare(
        `INSERT INTO ads_audit_log
         (id,actor_id,action,target_type,target_id)
         SELECT ?,?,?,?,? WHERE changes()=1`
      ).bind(
        crypto.randomUUID(),actor.id,
        `approve:${data.status}`,"creative",id
      )
    ]);

    if (results[0]?.meta?.changes !== 1)
      return reply({ error: "invalid_transition_or_not_found" }, 409);

    return reply({ id, status: data.status });
  }

  return reply({ error: "not_found" }, 404);
}
