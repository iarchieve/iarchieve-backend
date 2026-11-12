import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {handleTasBridge,handoffPayload} from '../src/modules/ads/tas-bridge.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const root='https://example.test/api/ads/admin/tas-requests';
const claimId='123e4567-e89b-42d3-a456-426614174000';
const token='a'.repeat(64);
const claim={id:claimId,proof_digest:'b'.repeat(64),verification_status:'pending'};
const assessment={id:'a1',verifier_id:'v1',verdict:'accepted',evidence_digest:'c'.repeat(64),assessment_digest:'d'.repeat(64),love_session_id:'s1',verifier_status:'active',controller_id:'group',affiliation_evidence_digest:'e'.repeat(64)};
function mock({row=claim,assessments=[assessment],conflicts=[],changes=1,stored=null}={}){
 const calls=[];
 const db={prepare(sql){const c={sql,values:[]};calls.push(c);return{bind(...v){c.values=v;return this},async first(){return sql.includes('ads_tas_handoff_requests')?stored:row},async all(){return{results:sql.includes('ads_verifier_controller_conflicts')?conflicts:assessments}},async run(){return{meta:{changes}}}}}};
 const env={ADS_DB:db,ADS_ADMIN_TOKEN:token};
 const call=(method,path,payload,auth=token)=>handleTasBridge(new Request(path,{method,headers:{Authorization:`Bearer ${auth}`,...(payload?{'Content-Type':'application/json'}:{})},...(payload?{body:JSON.stringify(payload)}:{})}),env);
 return {call,calls};
}
test('admin only, no database call before auth',async()=>{const x=mock();assert.equal((await x.call('POST',root,{claim_id:claimId},'wrong')).status,401);assert.equal(x.calls.length,0)});
test('rejects unexpected billing field',async()=>{const x=mock();assert.equal((await x.call('POST',root,{claim_id:claimId,billable:true})).status,422)});
test('rejects missing pending claim',async()=>{const x=mock({row:null});assert.equal((await x.call('POST',root,{claim_id:claimId})).status,409)});
test('rejects missing protected assessments',async()=>{const x=mock({assessments:[]});assert.equal((await x.call('POST',root,{claim_id:claimId})).status,409)});
test('rejects truncated assessments',async()=>{const x=mock({assessments:Array(201).fill(assessment)});assert.equal((await x.call('POST',root,{claim_id:claimId})).status,409)});
test('rejects truncated conflicts',async()=>{const x=mock({conflicts:Array(1001).fill({controller_a:'a',controller_b:'b',evidence_digest:'f'.repeat(64)})});assert.equal((await x.call('POST',root,{claim_id:claimId})).status,409)});
test('creates a pending immutable handoff, never bills or adjudicates',async()=>{const x=mock();const r=await x.call('POST',root,{claim_id:claimId});assert.equal(r.status,201);const b=await r.json();assert.equal(b.state,'awaiting_tas');assert.equal(b.billable,false);assert.equal(b.tas_adjudicated,false);const insert=x.calls.find(c=>c.sql.includes('INSERT INTO ads_tas_handoff_requests'));assert.ok(insert);assert.equal(JSON.parse(insert.values[1]).assessments[0].controller_id,'group')});
test('replayed insert rejected',async()=>{const x=mock({changes:0});assert.equal((await x.call('POST',root,{claim_id:claimId})).status,409)});
test('canonical snapshot preserves unverified semantics',()=>{const x=handoffPayload(claim,[assessment],[]);assert.equal(x.independence_certified,false);assert.equal(x.tas_adjudicated,false);assert.equal(x.billable,false)});
test('unknown request is 404',async()=>{const x=mock();assert.equal((await x.call('GET',root+'/'+claimId)).status,404)});
test('wrong method rejected',async()=>{const x=mock();assert.equal((await x.call('GET',root)).status,405)});
