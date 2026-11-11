import test from 'node:test';
import assert from 'node:assert/strict';
import { handleAdsDelivery } from '../src/modules/ads/delivery.mjs';
const token = 'A'.repeat(64);
const url = 'http://localhost/api/ads/delivery/next?placement_id=p1';
const call = (env, path = url, auth = true) => handleAdsDelivery(new Request(path, {
  headers: auth ? { Authorization: `Bearer ${token}` } : {}
}), env);
const placement = { id: 'p1', publisher_id: 'pub-test-001', status: 'approved' };
const campaign = { id: 'c1', name: 'Demo', format: 'display' };
function db(p = placement, c = campaign) {
  let n = 0;
  return { prepare() { return { bind() { return this; }, async first() { return n++ === 0 ? p : c; } }; } };
}
test('delivery requires publisher authentication', async () => {
  assert.equal((await call({ ADS_DB: db(), ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" }, url, false)).status, 401);
});
test('delivery requires D1', async () => {
  assert.equal((await call({ ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" })).status, 503);
});
test('delivery selects active campaign without recording billable impression', async () => {
  const result = await call({ ADS_DB: db(), ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" });
  assert.equal(result.status, 200);
  const body = await result.json();
  assert.equal(body.item.campaign_id, 'c1');
  assert.match(body.note, /no_budget_charge/);
});
test('delivery blocks unapproved placement', async () => {
  const result = await call({ ADS_DB: db({ ...placement, status: 'pending' }), ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" });
  assert.equal(result.status, 409);
});
test('delivery does not expose another publisher placement', async () => {
  const result = await call({ ADS_DB: db({ ...placement, publisher_id: 'someone-else' }), ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" });
  assert.equal(result.status, 404);
});
test('delivery handles no active campaign', async () => {
  const result = await call({ ADS_DB: db(placement, null), ADS_PUBLISHER_TOKEN: token, ADS_ALLOW_LEGACY_PUBLISHER_TOKEN: "true" });
  assert.equal((await result.json()).item, null);
});
