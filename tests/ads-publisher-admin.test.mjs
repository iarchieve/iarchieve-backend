import test from "node:test";
import assert from "node:assert/strict";
import { handlePublisherAdmin } from "../src/modules/ads/publisher-admin.mjs";

const token = "A".repeat(64);
const root = "http://localhost/api/ads/admin/publishers";

function request(path = root, method = "GET", body, credential = token) {
  const headers = { Authorization: `Bearer ${credential}` };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  return new Request(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

function database({
  accountStatus = "pending",
  accountExists = true,
  changes = 1
} = {}) {
  const calls = [];
  const batches = [];

  return {
    calls,
    batches,

    prepare(sql) {
      const statement = {
        bind(...params) {
          calls.push({ sql, params });
          return statement;
        },

        async first() {
          if (!accountExists) return null;

          return {
            id: "pub-001",
            status: accountStatus
          };
        },

        async all() {
          if (sql.includes("ads_publisher_credentials")) {
            return {
              results: [{
                id: "cred-001",
                publisher_id: "pub-001",
                status: "active",
                created_at: "2026-11-12",
                revoked_at: null
              }]
            };
          }

          return {
            results: [{
              id: "pub-001",
              name: "Publisher",
              role: "publisher",
              status: accountStatus
            }]
          };
        }
      };

      calls.push({ sql, params: [] });
      return statement;
    },

    async batch(statements) {
      batches.push(statements);
      return [
        { meta: { changes } },
        { meta: { changes } }
      ];
    }
  };
}

test("unauthenticated access is blocked", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(root, "GET", undefined, "B".repeat(64)),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 401);
  assert.equal(db.calls.length, 0);
});

test("requires database binding", async () => {
  const response = await handlePublisherAdmin(
    request(),
    { ADS_ADMIN_TOKEN: token }
  );

  assert.equal(response.status, 503);
});

test("administrator lists publisher accounts", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 200);

  const data = await response.json();

  assert.equal(data.items[0].id, "pub-001");

  assert.ok(db.calls.some(c =>
    c.sql.includes("WHERE role='publisher'")
  ));
});

test("administrator lists credential metadata without token hashes", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001/credentials`),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 200);

  const data = await response.json();

  assert.equal(data.publisher_id, "pub-001");
  assert.equal(data.items[0].id, "cred-001");

  const sql = db.calls.find(c =>
    c.sql.includes("FROM ads_publisher_credentials")
  )?.sql;

  assert.ok(sql);
  assert.ok(!sql.includes("token_hash"));
  assert.ok(!sql.includes("SELECT *"));
});

test("pending publisher can be approved", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 200);

  const data = await response.json();

  assert.equal(data.previous_status, "pending");
  assert.equal(data.status, "active");
  assert.equal(db.batches.length, 1);
  assert.equal(db.batches[0].length, 2);
});

test("active publisher can be suspended", async () => {
  const db = database({ accountStatus: "active" });

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "suspended" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "suspended");
});

test("suspended publisher can be reactivated", async () => {
  const db = database({ accountStatus: "suspended" });

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 200);
});

test("duplicate transition is rejected", async () => {
  const db = database({ accountStatus: "active" });

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 409);
  assert.equal(db.batches.length, 0);
});

test("invalid status is rejected", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "pending" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 422);
});

test("unknown publisher cannot be updated", async () => {
  const db = database({ accountExists: false });

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 404);
});

test("concurrent account changes are rejected", async () => {
  const db = database({ changes: 0 });

  const response = await handlePublisherAdmin(
    request(`${root}/pub-001`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 409);
});

test("invalid publisher ID is rejected", async () => {
  const db = database();

  const response = await handlePublisherAdmin(
    request(`${root}/bad%20id`, "PATCH", { status: "active" }),
    { ADS_ADMIN_TOKEN: token, ADS_DB: db }
  );

  assert.equal(response.status, 422);
});