const TOKEN_PATTERN = /^Bearer ([a-fA-F0-9]{64})$/;

export async function authenticatePublisher(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = TOKEN_PATTERN.exec(header);

  if (!match || !env.ADS_DB) return null;

  const bytes = new TextEncoder().encode(match[1].toLowerCase());
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  const hash = Array.from(
    new Uint8Array(digest),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");

  const account = await env.ADS_DB.prepare(
    `SELECT a.id AS publisher_id
     FROM ads_publisher_credentials c
     JOIN ads_accounts a ON a.id=c.publisher_id
     WHERE c.token_hash=?
       AND c.status='active'
       AND a.role='publisher'
       AND a.status='active'
     LIMIT 1`
  ).bind(hash).first();

  if (!account) return null;

  return {
    role: "publisher",
    id: account.publisher_id
  };
}