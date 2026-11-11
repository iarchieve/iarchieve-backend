import test from "node:test";
import assert from "node:assert/strict";
import { authenticatePublisher } from "../src/modules/ads/publisher-auth.mjs";

const token = "D".repeat(64);

async function tokenHash(value) {
  const bytes = new TextEncoder().encode(value.toLowerCase());
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

const expectedHash = await tokenHash(token);

function environment({
  accountStatus = "active",
  credentialStatus = "active",
  role = "publisher",
  publisherId = "pub-global-001",
  match = true
} = {}) {
  let queried = false;

  const env = {
    ADS_DB: {
      prepare(sql) {
        queried = true;
        assert.match(sql, /ads_publisher_credentials/);
        assert.match(sql, /JOIN ads_accounts/);
        assert.match(sql, /a\.status='active'/);
        assert.match(sql, /c\.status='active'/);
        assert.match(sql, /a\.role='publisher'/);

        return {
          bind(hash) {
            assert.equal(hash, expectedHash);
            return {
              async first() {
                if (!match || accountStatus !== "active" ||
                    credentialStatus !== "active" ||
                    role !== "publisher") {
                  return null;
                }
                return { publisher_id: publisherId };
              }
            };
          }
        };
      }
    }
  };

  return { env, wasQueried: () => queried };
}

function request(value = token) {
  return new Request("http://localhost/api/ads/delivery/next", {
    headers: {
      Authorization: `Bearer ${value}`
    }
  });
}

test("active publisher credential authenticates", async () => {
  const { env, wasQueried } = environment();
  const actor = await authenticatePublisher(request(), env);

  assert.deepEqual(actor, {
    role: "publisher",
    id: "pub-global-001"
  });
  assert.equal(wasQueried(), true);
});

test("suspended publisher is rejected", async () => {
  const { env } = environment({ accountStatus: "suspended" });
  assert.equal(await authenticatePublisher(request(), env), null);
});

test("pending publisher is rejected", async () => {
  const { env } = environment({ accountStatus: "pending" });
  assert.equal(await authenticatePublisher(request(), env), null);
});

test("revoked credential is rejected", async () => {
  const { env } = environment({ credentialStatus: "revoked" });
  assert.equal(await authenticatePublisher(request(), env), null);
});

test("non-publisher role is rejected", async () => {
  const { env } = environment({ role: "advertiser" });
  assert.equal(await authenticatePublisher(request(), env), null);
});

test("unknown token is rejected", async () => {
  const { env } = environment({ match: false });
  assert.equal(await authenticatePublisher(request(), env), null);
});

test("malformed token is rejected before database access", async () => {
  const { env, wasQueried } = environment();
  assert.equal(
    await authenticatePublisher(request("invalid"), env),
    null
  );
  assert.equal(wasQueried(), false);
});

test("missing database is rejected", async () => {
  assert.equal(await authenticatePublisher(request(), {}), null);
});