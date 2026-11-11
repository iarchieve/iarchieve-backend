import test from "node:test";
import assert from "node:assert/strict";
import { handleCredentialManagement } from "../src/modules/ads/credential-management.mjs";

const adminToken = "A".repeat(64);
const root = "http://localhost/api/ads/publisher-credentials";

function request(path = root, token = adminToken, body) {
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return new Request(path, {
    method: "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

function fakeDb({ publisher = true, credentialStatus = "active" } = {}) {
  const queries = [];
  const batches = [];

  return {
    queries,
    batches,
    prepare(sql) {
      return {
        bind(...params) {
          queries.push({ sql, params });
          return {
            async first() {
              if (sql.includes("FROM ads_accounts")) {
                return publisher ? { id: params[0] } : null;
              }
              if (sql.includes("FROM ads_publisher_credentials")) {
                return { id: params[0], publisher_id: "pub-001",
                         status: credentialStatus };
              }
              throw new Error("Unexpected lookup");
            }
          };
        }
      };
    },
    async batch(statements) {
      batches.push(statements);
      return [{ meta: { changes: 1 } }, { meta: { changes: 1 } }];
    }
  };
}

test("rejects unauthenticated issuer", async () => {
  const db = fakeDb();
  const result = await handleCredentialManagement(
    request(root, "B".repeat(64), { publisher_id: "pub-001" }),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: db }
  );
  assert.equal(result.status, 401);
  assert.equal(db.queries.length, 0);
});

test("requires D1", async () => {
  const result = await handleCredentialManagement(
    request(root, adminToken, { publisher_id: "pub-001" }),
    { ADS_ADMIN_TOKEN: adminToken }
  );
  assert.equal(result.status, 503);
});

test("rejects inactive publisher", async () => {
  const db = fakeDb({ publisher: false });
  const result = await handleCredentialManagement(
    request(root, adminToken, { publisher_id: "pub-001" }),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: db }
  );
  assert.equal(result.status, 422);
  assert.equal(db.batches.length, 0);
});

test("issues 64-character token without storing plaintext", async () => {
  const db = fakeDb();
  const result = await handleCredentialManagement(
    request(root, adminToken, { publisher_id: "pub-001" }),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: db }
  );
  assert.equal(result.status, 201);

  const body = await result.json();
  assert.match(body.token, /^[a-f0-9]{64}$/);
  assert.equal(body.publisher_id, "pub-001");
  assert.equal(db.batches.length, 1);

  const insert = db.queries.find(q =>
    q.sql.includes("INSERT INTO ads_publisher_credentials")
  );
  assert.ok(insert);
  assert.notEqual(insert.params[2], body.token);
  assert.match(insert.params[2], /^[a-f0-9]{64}$/);

  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(body.token)
  );
  const expected = Array.from(new Uint8Array(digest), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
  assert.equal(insert.params[2], expected);

  const audit = db.queries.find(q =>
    q.sql.includes("INSERT INTO ads_audit_log")
  );
  assert.ok(audit);
  assert.ok(!audit.params.includes(body.token));
});

test("revoke requires active credential", async () => {
  const db = fakeDb({ credentialStatus: "revoked" });
  const result = await handleCredentialManagement(
    request(`${root}/cred-001/revoke`),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: db }
  );
  assert.equal(result.status, 409);
  assert.equal(db.batches.length, 0);
});

test("revoke succeeds and creates audit in same batch", async () => {
  const db = fakeDb();
  const result = await handleCredentialManagement(
    request(`${root}/cred-001/revoke`),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: db }
  );
  assert.equal(result.status, 200);
  assert.equal((await result.json()).status, "revoked");
  assert.equal(db.batches.length, 1);

  assert.ok(db.queries.some(q =>
    q.sql.includes("SET status='revoked'")
  ));
  assert.ok(db.queries.some(q =>
    q.sql.includes("WHERE changes()=1")
  ));
});

test("unsupported method is rejected", async () => {
  const result = await handleCredentialManagement(
    new Request(root, {
      headers: { Authorization: `Bearer ${adminToken}` }
    }),
    { ADS_ADMIN_TOKEN: adminToken, ADS_DB: fakeDb() }
  );
  assert.equal(result.status, 405);
});