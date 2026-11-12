import test from 'node:test';
import assert from 'node:assert/strict';
import {handleVerifierIndependence} from '../src/modules/ads/verifier-independence.mjs';
const token='a'.repeat(64),digest='b'.repeat(64),root='https://example.test/api/ads/admin/verifier-independence';
const claim='123e4567-e89b-42d3-a456-426614174000';
function mock({changes=1,rows=[],conflicts=[],exists=true}={}){
 const calls=[];
 const db={prepare(sql){const c={sql,values:[]};calls.push(c);return{bind(...v){c.values=v;return this},async first(){return exists?{id:claim}:null},async all(){return{results:sql.includes('controller_conflicts')?conflicts:rows}},async run(){return{meta:{changes}}}}}};
 const env={ADS_DB:db,ADS_ADMIN_TOKEN:token};
 const call=(path,body,auth=token,method='POST')=>handleVerifierIndependence(new Request(path,{method,headers:{Authorization:`Bearer ${auth}`,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})}),env);
 return {call,calls};
}
test('rejects missing authorization before DB',async()=>{const x=mock();assert.equal((await x.call(root+'/affiliations',{verifier_id:'v',controller_id:'c',evidence_digest:digest},'bad')).status,401);assert.equal(x.calls.length,0)});
test('registers declared affiliation',async()=>{const x=mock();const r=await x.call(root+'/affiliations',{verifier_id:'v1',controller_id:'group',evidence_digest:digest});assert.equal(r.status,201);assert.equal((await r.json()).billable,false)});
test('rejects forged extra billing field',async()=>{const x=mock();assert.equal((await x.call(root+'/affiliations',{verifier_id:'v',controller_id:'g',evidence_digest:digest,billable:true})).status,422)});
test('affiliation duplicate rejected',async()=>{const x=mock({changes:0});assert.equal((await x.call(root+'/affiliations',{verifier_id:'v',controller_id:'g',evidence_digest:digest})).status,409)});
test('rejects same controller conflict',async()=>{const x=mock();assert.equal((await x.call(root+'/conflicts',{controller_a:'g',controller_b:'g',evidence_digest:digest})).status,422)});
test('canonicalizes conflict pair',async()=>{const x=mock();const r=await x.call(root+'/conflicts',{controller_a:'z',controller_b:'a',evidence_digest:digest});assert.equal(r.status,201);assert.deepEqual(x.calls[0].values.slice(0,2),['a','z'])});
test('unmapped attestations never count',async()=>{const x=mock({rows:[{verifier_id:'v1',verdict:'accepted',verifier_status:'active',controller_id:null}]});const r=await x.call(root+'/claims/'+claim,null,token,'GET');const b=await r.json();assert.equal(b.provisional_independent_count,0);assert.deepEqual(b.unmapped_verifiers,['v1']);assert.equal(b.independence_certified,false)});
test('same controller counted at most once',async()=>{const x=mock({rows:[{verifier_id:'v1',verifier_status:'active',controller_id:'g'},{verifier_id:'v2',verifier_status:'active',controller_id:'g'}]});const b=await (await x.call(root+'/claims/'+claim,null,token,'GET')).json();assert.equal(b.provisional_independent_count,1)});
test('declared conflict reduces provisional independence',async()=>{const x=mock({rows:[{verifier_id:'v1',verifier_status:'active',controller_id:'a'},{verifier_id:'v2',verifier_status:'active',controller_id:'b'}],conflicts:[{controller_a:'a',controller_b:'b'}]});const b=await (await x.call(root+'/claims/'+claim,null,token,'GET')).json();assert.equal(b.provisional_independent_count,1)});
test('revoked verifier excluded',async()=>{const x=mock({rows:[{verifier_id:'v1',verifier_status:'revoked',controller_id:'g'}]});const b=await (await x.call(root+'/claims/'+claim,null,token,'GET')).json();assert.equal(b.provisional_independent_count,0)});
