import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { handleVerifierAdmin } from '../src/modules/ads/verifier-admin.mjs';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const token = 'a'.repeat(64);
const endpoint = 'https://example.test/api/ads/admin/verifiers';
const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
const publicKey = { kty:jwk.kty, crv:jwk.crv, x:jwk.x, y:jwk.y };
function fixture(changes=1) {
  const calls = [];
  const env = { ADS_ADMIN_TOKEN:token, ADS_DB: { prepare(sql) {
    const call = { sql, bind:[] }; calls.push(call);
    return { bind(...v){ call.bind = v; return this; }, async run(){ return { meta:{ changes } }; }, async all(){ return { results:[] }; } };
  } } };
  const post = (body, auth=`Bearer ${token}`, url=endpoint) => handleVerifierAdmin(
    new Request(url, {method:'POST',headers:{'Content-Type':'application/json',Authorization:auth},body:JSON.stringify(body)}),env);
  const get = (auth=`Bearer ${token}`) => handleVerifierAdmin(new Request(endpoint,{headers:{Authorization:auth}}),env);
  return {post,get,calls};
}
test('valid P-256 public key registered without private material', async()=>{
  const f=fixture();const r=await f.post({ verifier_id:'verifier-key-v1',public_key_jwk:publicKey });
  assert.equal(r.status,201);assert.equal((await r.json()).billable,false);
  assert.equal(f.calls.length,1);const saved=JSON.parse(f.calls[0].bind[1]);
  assert.deepEqual(saved,publicKey);assert.equal(Object.hasOwn(saved,'d'),false);
});
test('no authorization cannot access DB',async()=>{
  const f=fixture();assert.equal((await f.post({verifier_id:'v',public_key_jwk:publicKey},'')).status,401);
  assert.equal((await f.get('')).status,401);assert.equal(f.calls.length,0);
});
test('rejects private JWK or extra fields',async()=>{
  const f=fixture();assert.equal((await f.post({verifier_id:'v',public_key_jwk:{...publicKey,d:'secret'}})).status,422);
  assert.equal((await f.post({verifier_id:'v',public_key_jwk:publicKey,billable:true})).status,422);
  assert.equal(f.calls.length,0);
});
test('rejects invalid point on P-256',async()=>{
  const f=fixture();assert.equal((await f.post({verifier_id:'v',public_key_jwk:{...publicKey,x:'A'.repeat(43),y:'A'.repeat(43)}})).status,422);
  assert.equal(f.calls.length,0);
});
test('DB uniqueness or duplicate returns conflict',async()=>{
  const f=fixture(0);assert.equal((await f.post({verifier_id:'v',public_key_jwk:publicKey})).status,409);
});
test('revoke active verifier and reject replay',async()=>{
  const f=fixture();const r=await f.post({},undefined,`${endpoint}/v/revoke`);
  assert.equal(r.status,200);assert.equal((await r.json()).status,'revoked');
  assert.match(f.calls[0].sql,/status='active'/);
  const already=fixture(0);assert.equal((await already.post({},undefined,`${endpoint}/v/revoke`)).status,409);
});
test('reject revoke body injection and invalid ID',async()=>{
  const f=fixture();assert.equal((await f.post({status:'active'},undefined,`${endpoint}/v/revoke`)).status,422);
  assert.equal((await f.post({},undefined,`${endpoint}/bad%2Fid/revoke`)).status,422);
  assert.equal(f.calls.length,0);
});
test('admin can list only public status metadata',async()=>{
  const f=fixture();const r=await f.get();assert.equal(r.status,200);
  assert.deepEqual((await r.json()).items,[]);
  assert.doesNotMatch(f.calls[0].sql,/public_key_jwk/);
});
test('GET/POST method guard',async()=>{
  const f=fixture();const r=await handleVerifierAdmin(new Request(endpoint,{method:'DELETE',headers:{Authorization:`Bearer ${token}`}}),{ADS_ADMIN_TOKEN:token,ADS_DB:{}});
  assert.equal(r.status,405);
});
