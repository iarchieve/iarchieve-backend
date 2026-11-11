import test from "node:test";
import assert from "node:assert/strict";
import { handleCredentialManagement } from "../src/modules/ads/credential-management.mjs";

const admin = "A".repeat(64);
const root = "http://localhost/api/ads/publisher-credentials";
const url = `${root}/old-credential/rotate`;

function request(token = admin, path = url) {
  return new Request(path, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` }
  });
}

function fakeDb({
  credentialStatus = "active",
  exists = true,
  changes = [1, 1, 1, 1]
} = {}) {
  const queries = [];
  const batches = [];

  return {
    queries,
    batches,

    prepare(sql) {
      const statement = {
        bind(...params) {
          queries.push({ sql, params });
          return statement;
        },

        async first() {
          if (!sql.includes("FROM ads_publisher_credentials")) {
            throw new Error("Unexpected lookup");
          }

          return exists ? {
            id: "old-credential",
            publisher_id: "publisher-1",
            status: credentialStatus
          } : null;
        }
      };

      return statement;
    },

    async batch(statements) {
      batches.push(statements);
      return changes.map(value => ({
        meta: { changes: value }
      }));
    }
  };
}

test("admin can atomically rotate an active credential", async () => {
  const db = fakeDb();

  const response = await handleCredentialManagement(
    request(),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: db }
  );

  assert.equal(response.status, 201);

  const data = await response.json();

  assert.equal(data.previous_credential_id, "old-credential");
  assert.equal(data.publisher_id, "publisher-1");
  assert.match(data.token, /^[a-f0-9]{64}$/);
  assert.notEqual(data.credential_id, "old-credential");

  assert.equal(db.batches.length, 1);
  assert.equal(db.batches[0].length, 4);

  const update = db.queries.find(q =>
    q.sql.includes("UPDATE ads_publisher_credentials")
  );

  const insert = db.queries.find(q =>
    q.sql.includes("INSERT INTO ads_publisher_credentials")
  );

  assert.ok(update);
  assert.ok(insert);
  assert.match(update.sql, /status='revoked'/);
  assert.match(update.sql, /WHERE id=\? AND status='active'/);
  assert.match(insert.sql, /WHERE changes\(\)=1/);

  const hash = insert.params[2];
  assert.match(hash, /^[a-f0-9]{64}$/);
  assert.notEqual(hash, data.token);

  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(data.token)
  );
  const expectedHash = Array.from(
    new Uint8Array(digest),
    b => b.toString(16).padStart(2, "0")
  ).join("");

  assert.equal(hash, expectedHash);

  const auditQueries = db.queries.filter(q =>
    q.sql.includes("INSERT INTO ads_audit_log")
  );
  assert.equal(auditQueries.length, 2);

  for (const audit of auditQueries) {
    assert.match(audit.sql, /WHERE changes\(\)=1/);
    assert.ok(!audit.params.includes(data.token));
  }
});

test("only admin may rotate credentials", async () => {
  const db = fakeDb();

  const response = await handleCredentialManagement(
    request("B".repeat(64)),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: db }
  );

  assert.equal(response.status, 401);
  assert.equal(db.batches.length, 0);
});

test("unknown credential cannot be rotated", async () => {
  const db = fakeDb({ exists: false });

  const response = await handleCredentialManagement(
    request(),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: db }
  );

  assert.equal(response.status, 404);
  assert.equal(db.batches.length, 0);
});

test("revoked credential cannot be rotated", async () => {
  const db = fakeDb({ credentialStatus: "revoked" });

  const response = await handleCredentialManagement(
    request(),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: db }
  );

  assert.equal(response.status, 409);
  assert.equal(db.batches.length, 0);
});

test("concurrent update does not return a new token", async () => {
  const db = fakeDb({ changes: [0, 0, 0, 0] });

  const response = await handleCredentialManagement(
    request(),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: db }
  );

  assert.equal(response.status, 409);

  const data = await response.json();
  assert.equal(data.error, "concurrent_update");
  assert.equal(data.token, undefined);
});

test("rotation rejects unsupported methods", async () => {
  const response = await handleCredentialManagement(
    new Request(url, {
      headers: { Authorization: `Bearer ${admin}` }
    }),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: fakeDb() }
  );

  assert.equal(response.status, 405);
});

test("malformed credential ID is rejected", async () => {
  const response = await handleCredentialManagement(
    request(admin, `${root}/bad%20id/rotate`),
    { ADS_ADMIN_TOKEN: admin, ADS_DB: fakeDb() }
  );

  assert.equal(response.status, 422);
});