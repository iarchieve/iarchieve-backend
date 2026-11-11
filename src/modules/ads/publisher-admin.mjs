const respond = (data, status = 200) => Response.json(data, {
  status,
  headers: { "Cache-Control": "no-store" }
});

const idPattern = /^[a-zA-Z0-9_-]{1,128}$/;

function authorized(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(
    request.headers.get("Authorization") || ""
  );

  const secret = env.ADS_ADMIN_TOKEN;

  if (!match || typeof secret !== "string" ||
      !/^[a-fA-F0-9]{64}$/.test(secret)) return false;

  const actual = match[1].toLowerCase();
  const expected = secret.toLowerCase();
  let difference = 0;

  for (let i = 0; i < 64; i++) {
    difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return difference === 0;
}

async function readJson(request) {
  if (!(request.headers.get("Content-Type") || "")
      .toLowerCase().includes("application/json")) {
    return { error: "content_type_required" };
  }

  const text = await request.text();

  if (new TextEncoder().encode(text).length > 4096) {
    return { error: "body_too_large" };
  }

  try {
    const data = JSON.parse(text);

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { error: "invalid_json" };
    }

    return { data };
  } catch {
    return { error: "invalid_json" };
  }
}

const transitions = {
  pending: ["active", "suspended"],
  active: ["suspended"],
  suspended: ["active"]
};

export async function handlePublisherAdmin(request, env) {
  if (!authorized(request, env)) {
    return respond({ error: "unauthorized" }, 401);
  }

  if (!env.ADS_DB) {
    return respond({ error: "database_unavailable" }, 503);
  }

  const path = new URL(request.url).pathname;
  const root = "/api/ads/admin/publishers";
  const accountMatch = /^\/api\/ads\/admin\/publishers\/([^/]+)$/.exec(path);
  const credentialMatch =
    /^\/api\/ads\/admin\/publishers\/([^/]+)\/credentials$/.exec(path);

  if (path === root) {
    if (request.method !== "GET") {
      return respond({ error: "method_not_allowed" }, 405);
    }

    const result = await env.ADS_DB.prepare(
      "SELECT id,name,role,status,created_at " +
      "FROM ads_accounts WHERE role='publisher' " +
      "ORDER BY created_at DESC,id DESC LIMIT 100"
    ).all();

    return respond({ items: result.results });
  }

  if (credentialMatch) {
    if (request.method !== "GET") {
      return respond({ error: "method_not_allowed" }, 405);
    }

    const publisherId = decodeURIComponent(credentialMatch[1]);

    if (!idPattern.test(publisherId)) {
      return respond({ error: "invalid_publisher_id" }, 422);
    }

    const publisher = await env.ADS_DB.prepare(
      "SELECT id FROM ads_accounts WHERE id=? AND role='publisher'"
    ).bind(publisherId).first();

    if (!publisher) {
      return respond({ error: "not_found" }, 404);
    }

    const result = await env.ADS_DB.prepare(
      "SELECT id,publisher_id,status,created_at,revoked_at " +
      "FROM ads_publisher_credentials WHERE publisher_id=? " +
      "ORDER BY created_at DESC,id DESC LIMIT 100"
    ).bind(publisherId).all();

    return respond({ publisher_id: publisherId, items: result.results });
  }

  if (!accountMatch) {
    return respond({ error: "not_found" }, 404);
  }

  if (request.method !== "PATCH") {
    return respond({ error: "method_not_allowed" }, 405);
  }

  const publisherId = decodeURIComponent(accountMatch[1]);

  if (!idPattern.test(publisherId)) {
    return respond({ error: "invalid_publisher_id" }, 422);
  }

  const input = await readJson(request);

  if (input.error) {
    return respond({ error: input.error }, 400);
  }

  const { status } = input.data;

  if (!["active", "suspended"].includes(status) ||
      Object.keys(input.data).some(key => key !== "status")) {
    return respond({ error: "invalid_status" }, 422);
  }

  const publisher = await env.ADS_DB.prepare(
    "SELECT id,status FROM ads_accounts " +
    "WHERE id=? AND role='publisher'"
  ).bind(publisherId).first();

  if (!publisher) {
    return respond({ error: "not_found" }, 404);
  }

  if (!transitions[publisher.status]?.includes(status)) {
    return respond({ error: "invalid_transition" }, 409);
  }

  const update = env.ADS_DB.prepare(
    "UPDATE ads_accounts SET status=? " +
    "WHERE id=? AND role='publisher' AND status=?"
  ).bind(status, publisherId, publisher.status);

  const audit = env.ADS_DB.prepare(
    "INSERT INTO ads_audit_log " +
    "(id,actor_id,action,target_type,target_id) " +
    "SELECT ?,?,?,?,? WHERE changes()=1"
  ).bind(
    crypto.randomUUID(),
    "dev-admin",
    `publisher:${publisher.status}->${status}`,
    "publisher",
    publisherId
  );

  const results = await env.ADS_DB.batch([update, audit]);

  if (results[0]?.meta?.changes !== 1 ||
      results[1]?.meta?.changes !== 1) {
    return respond({ error: "concurrent_update" }, 409);
  }

  return respond({
    id: publisherId,
    previous_status: publisher.status,
    status
  });
}