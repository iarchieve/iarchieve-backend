const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const json = (data, status=200) => Response.json(data, {status,headers:{'Cache-Control':'no-store'}});
function authorized(req, env) {
  const m=/^Bearer ([a-fA-F0-9]{64})$/.exec(req.headers.get('Authorization')||'');
  const e=env.ADS_ADMIN_TOKEN;
  if (!m || typeof e!=='string' || !/^[a-fA-F0-9]{64}$/.test(e)) return false;
  let delta=0; for(let i=0;i<64;i++) delta|=m[1].toLowerCase().charCodeAt(i)^e.toLowerCase().charCodeAt(i);
  return delta===0;
}
async function body(req){
  if(!/^application\/json(?:\s*;|$)/i.test(req.headers.get('Content-Type')||'')) return {error:'content_type_required',status:400};
  const reader=req.body?.getReader(); if(!reader) return {error:'invalid_json',status:400};
  let size=0; const parts=[];
  try{for(;;){let {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2048){await reader.cancel();return {error:'body_too_large',status:413}}parts.push(value)}
  const all=new Uint8Array(size);let off=0;for(const p of parts){all.set(p,off);off+=p.byteLength}const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));
  if(!data||typeof data!=='object'||Array.isArray(data)) throw Error();return {data};}
  catch{return {error:'invalid_json',status:400}}
}
const valid = (x) => typeof x==='string' && ID.test(x);
export async function handleVerifierIndependence(req,env){
  if(!authorized(req,env))return json({error:'unauthorized'},401);
  if(!env.ADS_DB)return json({error:'database_unavailable'},503);
  const path=new URL(req.url).pathname;
  const root='/api/ads/admin/verifier-independence';
  const assess=/^\/api\/ads\/admin\/verifier-independence\/claims\/([^/]+)$/.exec(path);
  if(assess){
    if(req.method!=='GET')return json({error:'method_not_allowed'},405);
    if(!UUID.test(assess[1]))return json({error:'invalid_claim'},422);
    const claimId=assess[1].toLowerCase();
    const claim=await env.ADS_DB.prepare('SELECT id FROM ads_impression_claims WHERE id=?').bind(claimId).first();
    if(!claim)return json({error:'claim_not_found'},404);
    const r=await env.ADS_DB.prepare(`SELECT a.verifier_id,a.verdict,v.status AS verifier_status,f.controller_id,f.evidence_digest AS affiliation_evidence
      FROM ads_verification_assessments a
      LEFT JOIN ads_verifier_registry v ON v.id=a.verifier_id
      LEFT JOIN ads_verifier_affiliations f ON f.verifier_id=a.verifier_id
      WHERE a.claim_id=? ORDER BY a.verifier_id`).bind(claimId).all();
    const rows=r.results||[];
    const controllers=[...new Set(rows.filter(x=>x.controller_id&&x.verifier_status==='active').map(x=>x.controller_id))].sort();
    const conflicts=await env.ADS_DB.prepare('SELECT controller_a,controller_b FROM ads_verifier_controller_conflicts').all();
    const conflictPairs=(conflicts.results||[]).filter(x=>controllers.includes(x.controller_a)&&controllers.includes(x.controller_b));
    const missing=rows.filter(x=>!x.controller_id).map(x=>x.verifier_id);
    const inactive=rows.filter(x=>x.verifier_status!=='active').map(x=>x.verifier_id);
    // Conservative upper bound: one per controller, conflicts reduce independent count.
    // Exact maximum independent set for small numbers; conservative zero for oversized graphs.
    let independent=0;
    if(controllers.length<=20){
      const blocked=conflictPairs.map(x=>[controllers.indexOf(x.controller_a),controllers.indexOf(x.controller_b)]);
      for(let mask=0;mask<(1<<controllers.length);mask++){
        const count=popcount(mask);if(count<=independent)continue;
        if(blocked.every(([a,b])=>!((mask&(1<<a))&&(mask&(1<<b)))))independent=count;
      }
    }
    return json({claim_id:claimId,assessment_count:rows.length,eligible_controller_count:controllers.length,
      provisional_independent_count:independent,unmapped_verifiers:missing,inactive_verifiers:inactive,
      disclosed_conflicts:conflictPairs,source:'admin_declared_unverified',
      independence_certified:false,tas_adjudicated:false,final_verification:false,billable:false});
  }
  if(path!==root+'/affiliations'&&path!==root+'/conflicts')return json({error:'not_found'},404);
  if(req.method!=='POST')return json({error:'method_not_allowed'},405);
  const parsed=await body(req);if(parsed.error)return json({error:parsed.error},parsed.status);
  const x=parsed.data;
  if(path.endsWith('/affiliations')){
    if(Object.keys(x).sort().join(',')!=='controller_id,evidence_digest,verifier_id'||!valid(x.verifier_id)||!valid(x.controller_id)||!HEX.test(x.evidence_digest))return json({error:'invalid_affiliation'},422);
    try{const result=await env.ADS_DB.prepare(`INSERT INTO ads_verifier_affiliations(verifier_id,controller_id,evidence_digest)
      SELECT id,?,? FROM ads_verifier_registry WHERE id=? AND status='active'`).bind(x.controller_id,x.evidence_digest,x.verifier_id).run();
      if(result.meta?.changes!==1)return json({error:'affiliation_conflict'},409);
      return json({verifier_id:x.verifier_id,controller_id:x.controller_id,attestation:'admin_declared_unverified',billable:false},201);
    }catch{return json({error:'affiliation_conflict'},409)}
  }
  if(Object.keys(x).sort().join(',')!=='controller_a,controller_b,evidence_digest'||!valid(x.controller_a)||!valid(x.controller_b)||x.controller_a===x.controller_b||!HEX.test(x.evidence_digest))return json({error:'invalid_conflict'},422);
  const [a,b]=[x.controller_a,x.controller_b].sort();
  try{const result=await env.ADS_DB.prepare('INSERT INTO ads_verifier_controller_conflicts(controller_a,controller_b,evidence_digest) VALUES(?,?,?)').bind(a,b,x.evidence_digest).run();
    if(result.meta?.changes!==1)return json({error:'conflict_exists'},409);
    return json({controller_a:a,controller_b:b,attestation:'admin_declared_unverified',billable:false},201);
  }catch{return json({error:'conflict_exists'},409)}
}
function popcount(n){let c=0;while(n){n&=n-1;c++}return c}
