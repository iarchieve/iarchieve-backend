// PR18: immutable TAS handoff, not adjudication or billing.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{64}$/;
const ROOT = '/api/ads/admin/tas-requests';
const json = (value, status=200) => Response.json(value, {status,headers:{'Cache-Control':'no-store'}});

function admin(request, env) {
  const match=/^Bearer ([a-fA-F0-9]{64})$/.exec(request.headers.get('Authorization')||'');
  const secret=env.ADS_ADMIN_TOKEN;
  if(!match || typeof secret!=='string' || !HEX.test(secret.toLowerCase())) return false;
  let diff=0; for(let i=0;i<64;i++) diff |= match[1].toLowerCase().charCodeAt(i)^secret.toLowerCase().charCodeAt(i);
  return diff===0;
}
async function body(request) {
  if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type')||'')) return {error:'content_type_required',status:400};
  const length=request.headers.get('Content-Length');
  if(length!==null && (!Number.isSafeInteger(Number(length)) || Number(length)<0 || Number(length)>1024)) return {error:'body_too_large',status:413};
  try {
    const reader=request.body?.getReader(); if(!reader) return {error:'invalid_json',status:400};
    let total=0;const chunks=[];
    for(;;){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>1024){await reader.cancel();return {error:'body_too_large',status:413};} chunks.push(value)}
    const bytes=new Uint8Array(total);let off=0;for(const chunk of chunks){bytes.set(chunk,off);off+=chunk.length}
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if(!value || typeof value!=='object' || Array.isArray(value)) return {error:'invalid_json',status:400};
    return {value};
  }catch{return {error:'invalid_json',status:400}}
}
async function sha(value){const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return Array.from(new Uint8Array(hash),n=>n.toString(16).padStart(2,'0')).join('')}

// Canonical JSON is produced by an explicit property order and ordered SQL results.
export function handoffPayload(claim, assessments, conflicts) {
  return {
    schema:'iarchieve.ads.tas-handoff.v1',
    claim_id:claim.id,
    impression_proof_digest:claim.proof_digest,
    claim_verification_status:claim.verification_status,
    assessments:assessments.map(a=>({
      assessment_id:a.id, verifier_id:a.verifier_id, verdict:a.verdict,
      evidence_digest:a.evidence_digest, assessment_digest:a.assessment_digest,
      love_session_id:a.love_session_id, verifier_status:a.verifier_status,
      controller_id:a.controller_id, affiliation_evidence_digest:a.affiliation_evidence_digest
    })),
    declared_controller_conflicts:conflicts.map(c=>({
      controller_a:c.controller_a,controller_b:c.controller_b,evidence_digest:c.evidence_digest
    })),
    independence_certified:false, tas_adjudicated:false, final_verification:false, billable:false
  };
}
export async function handleTasBridge(request,env) {
  if(!admin(request,env))return json({error:'unauthorized'},401);
  if(!env.ADS_DB)return json({error:'database_unavailable'},503);
  const path=new URL(request.url).pathname;
  const single=/^\/api\/ads\/admin\/tas-requests\/([^/]+)$/.exec(path);
  if(single){
    if(request.method!=='GET')return json({error:'method_not_allowed'},405);
    if(!UUID.test(single[1]))return json({error:'invalid_id'},422);
    const row=await env.ADS_DB.prepare('SELECT id,claim_id,payload_json,payload_digest,state,created_at FROM ads_tas_handoff_requests WHERE id=?').bind(single[1].toLowerCase()).first();
    if(!row)return json({error:'not_found'},404);
    const recomputed=await sha(row.payload_json);
    if(recomputed!==row.payload_digest)return json({error:'handoff_integrity_failure'},409);
    return json({request_id:row.id,claim_id:row.claim_id,payload:JSON.parse(row.payload_json),payload_digest:row.payload_digest,state:row.state,created_at:row.created_at,tas_adjudicated:false,billable:false});
  }
  if(path!==ROOT)return json({error:'not_found'},404);
  if(request.method!=='POST')return json({error:'method_not_allowed'},405);
  const input=await body(request);if(input.error)return json({error:input.error},input.status);
  if(Object.keys(input.value).join(',')!=='claim_id' || typeof input.value.claim_id!=='string' || !UUID.test(input.value.claim_id))return json({error:'invalid_handoff'},422);
  const id=input.value.claim_id.toLowerCase();
  const claim=await env.ADS_DB.prepare('SELECT id,proof_digest,verification_status FROM ads_impression_claims WHERE id=? AND verification_status=\'pending\'').bind(id).first();
  if(!claim)return json({error:'claim_not_available'},409);
  const assessmentResult=await env.ADS_DB.prepare(`SELECT a.id,a.verifier_id,a.verdict,a.evidence_digest,a.assessment_digest,a.love_session_id,
    v.status AS verifier_status,f.controller_id,f.evidence_digest AS affiliation_evidence_digest
    FROM ads_verification_assessments a
    JOIN ads_verifier_registry v ON v.id=a.verifier_id
    LEFT JOIN ads_verifier_affiliations f ON f.verifier_id=a.verifier_id
    WHERE a.claim_id=? AND a.love_session_id IS NOT NULL ORDER BY a.verifier_id,a.id LIMIT 201`).bind(id).all();
  const assessments=assessmentResult.results||[];
  if(!assessments.length)return json({error:'no_love_assessments'},409);
  if(assessments.length>200)return json({error:'assessment_limit'},409);
  // No asserted independent count; a missing affiliation cannot be silently treated as independent.
  const conflictsResult=await env.ADS_DB.prepare(`SELECT controller_a,controller_b,evidence_digest FROM ads_verifier_controller_conflicts
    ORDER BY controller_a,controller_b LIMIT 1001`).all();
  const conflicts=conflictsResult.results||[];
  if(conflicts.length>1000)return json({error:'conflict_limit'},409);
  const payload=handoffPayload(claim,assessments,conflicts);
  const serialized=JSON.stringify(payload);
  const digest=await sha(serialized);
  const requestId=crypto.randomUUID();
  try{
    // Claim state is rechecked within the write. UNIQUE(claim_id) rejects concurrent/replayed requests.
    const result=await env.ADS_DB.prepare(`INSERT INTO ads_tas_handoff_requests(id,claim_id,payload_json,payload_digest)
      SELECT ?,id,?,? FROM ads_impression_claims WHERE id=? AND verification_status='pending'`).bind(requestId,serialized,digest,id).run();
    if(result.meta?.changes!==1)return json({error:'handoff_conflict'},409);
  }catch{return json({error:'handoff_conflict'},409)}
  return json({request_id:requestId,claim_id:id,payload_digest:digest,state:'awaiting_tas',tas_adjudicated:false,final_verification:false,billable:false},201);
}
