const respond = (body, status = 200) => Response.json(body, {
  status,
  headers: {
    "Cache-Control": "no-store",
    "Pragma": "no-cache"
  }
});

const tokenPattern = /^[a-fA-F0-9]{64}$/;
const idPattern = /^[a-zA-Z0-9_-]{1,128}$/;

function adminAuthorized(request, env) {
  const match = /^Bearer ([a-fA-F0-9]{64})$/.exec(
    request.headers.get("Authorization") || ""
  );
  const secret = env.ADS_ADMIN_TOKEN;

  if (!match || typeof secret !== "string" ||
      !tokenPattern.test(secret)) return false;

  const actual = match[1].toLowerCase();
  const expected = secret.toLowerCase();
  let difference = 0;

  for (let i = 0; i < 64; i++) {
    difference |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return difference === 0;
}

async function readBody(request) {
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

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(token.toLowerCase())
  );
  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

export async function handleCredentialManagement(request, env) {
  if (!adminAuthorized(request, env)) {
    return respond({ error: "unauthorized" }, 401);
  }

  if (!env.ADS_DB) {
    return respond({ error: "database_unavailable" }, 503);
  }

  const path = new URL(request.url).pathname;
  const root = "/api/ads/publisher-credentials";
  const revoke = /^\/api\/ads\/publisher-credentials\/([^/]+)\/revoke$/.exec(path);
  const rotate = /^\/api\/ads\/publisher-credentials\/([^/]+)\/rotate$/.exec(path);

  if (path !== root && !revoke && !rotate) {
    return respond({ error: "not_found" }, 404);
  }

  if (request.method !== "POST") {
    return respond({ error: "method_not_allowed" }, 405);
  }

  if (path === root) {
    const input = await readBody(request);
    if (input.error) return respond({ error: input.error }, 400);

    const { publisher_id: publisherId } = input.data;

    if (!idPattern.test(publisherId || "") ||
        Object.keys(input.data).some(key => key !== "publisher_id")) {
      return respond({ error: "invalid_publisher_id" }, 422);
    }

    const publisher = await env.ADS_DB.prepare(
      "SELECT id FROM ads_accounts WHERE id=? AND role='publisher' AND status='active'"
    ).bind(publisherId).first();

    if (!publisher) {
      return respond({ error: "publisher_not_active" }, 422);
    }

    const token = generateToken();
    const tokenHash = await hashToken(token);
    const credentialId = crypto.randomUUID();

    const insert = env.ADS_DB.prepare(
      "INSERT INTO ads_publisher_credentials " +
      "(id,publisher_id,token_hash,status) VALUES (?,?,?,'active')"
    ).bind(credentialId, publisherId, tokenHash);

    const audit = env.ADS_DB.prepare(
      "INSERT INTO ads_audit_log " +
      "(id,actor_id,action,target_type,target_id) VALUES (?,?,?,?,?)"
    ).bind(
      crypto.randomUUID(),
      "dev-admin",
      "credential:issued",
      "publisher_credential",
      credentialId
    );

    await env.ADS_DB.batch([insert, audit]);

    return respond({
      credential_id: credentialId,
      publisher_id: publisherId,
      token,
      status: "active",
      notice: "Store this token securely. It will not be shown again."
    }, 201);
  }

  const credentialId = decodeURIComponent((rotate || revoke)[1]);

  if (!idPattern.test(credentialId)) {
    return respond({ error: "invalid_credential_id" }, 422);
  }

  const credential = await env.ADS_DB.prepare(
    "SELECT id,publisher_id,status FROM ads_publisher_credentials WHERE id=?"
  ).bind(credentialId).first();

  if (!credential) return respond({ error: "not_found" }, 404);

  if (credential.status !== "active") {
    return respond({ error: "credential_not_active" }, 409);
  }

  if (rotate) {
    const token = generateToken();
    const hash = await hashToken(token);
    const newId = crypto.randomUUID();

    // D1 batch statements execute in a transaction.
    // The INSERT is conditional on the previous UPDATE.
    // A failed statement rolls back the complete batch.
    const retireOld = env.ADS_DB.prepare(
      "UPDATE ads_publisher_credentials " +
      "SET status='revoked',revoked_at=CURRENT_TIMESTAMP " +
      "WHERE id=? AND status='active'"
    ).bind(credentialId);

    const insertNew = env.ADS_DB.prepare(
      "INSERT INTO ads_publisher_credentials " +
      "(id,publisher_id,token_hash,status) " +
      "SELECT ?,?,?, 'active' WHERE changes()=1"
    ).bind(newId, credential.publisher_id, hash);

    const auditRetired = env.ADS_DB.prepare(
      "INSERT INTO ads_audit_log " +
      "(id,actor_id,action,target_type,target_id) " +
      "SELECT ?,?,?,?,? WHERE changes()=1"
    ).bind(
      crypto.randomUUID(),
      "dev-admin",
      "credential:rotated_out",
      "publisher_credential",
      credentialId
    );

    const auditIssued = env.ADS_DB.prepare(
      "INSERT INTO ads_audit_log " +
      "(id,actor_id,action,target_type,target_id) " +
      "SELECT ?,?,?,?,? WHERE changes()=1"
    ).bind(
      crypto.randomUUID(),
      "dev-admin",
      "credential:rotated_in",
      "publisher_credential",
      newId
    );

    const results = await env.ADS_DB.batch([
      retireOld, insertNew, auditRetired, auditIssued
    ]);

    if (results.length !== 4 ||
        results.some(result => result?.meta?.changes !== 1)) {
      return respond({ error: "concurrent_update" }, 409);
    }

    return respond({
      previous_credential_id: credentialId,
      credential_id: newId,
      publisher_id: credential.publisher_id,
      token,
      status: "active",
      notice: "Store this token securely. It will not be shown again."
    }, 201);
  }

  const update = env.ADS_DB.prepare(
    "UPDATE ads_publisher_credentials " +
    "SET status='revoked',revoked_at=CURRENT_TIMESTAMP " +
    "WHERE id=? AND status='active'"
  ).bind(credentialId);

  const audit = env.ADS_DB.prepare(
    "INSERT INTO ads_audit_log " +
    "(id,actor_id,action,target_type,target_id) " +
    "SELECT ?,?,?,?,? WHERE changes()=1"
  ).bind(
    crypto.randomUUID(),
    "dev-admin",
    "credential:revoked",
    "publisher_credential",
    credentialId
  );

  const result = await env.ADS_DB.batch([update, audit]);

  if (result[0]?.meta?.changes !== 1) {
    return respond({ error: "concurrent_update" }, 409);
  }

  return respond({
    credential_id: credentialId,
    publisher_id: credential.publisher_id,
    status: "revoked"
  });
}