const reply = (data, status = 200) => Response.json(data, {
  status, headers: { 'Cache-Control': 'no-store' }
});

function authorized(request, env) {
  const header = /^Bearer ([a-fA-F0-9]{64})$/.exec(request.headers.get('Authorization') || '');
  const secret = env.ADS_PUBLISHER_TOKEN;
  if (!header || typeof secret !== 'string' || !/^[a-fA-F0-9]{64}$/.test(secret)) return false;
  let difference = 0;
  const a = header[1].toUpperCase();
  const b = secret.toUpperCase();
  for (let i = 0; i < 64; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

export async function handleAdsDelivery(request, env) {
  if (!authorized(request, env)) return reply({ error: 'unauthorized' }, 401);
  if (!env.ADS_DB) return reply({ error: 'database_unavailable' }, 503);
  const path = new URL(request.url).pathname;
  if (path !== '/api/ads/delivery/next' || request.method !== 'GET') {
    return reply({ error: 'not_found' }, 404);
  }
  const placementId = new URL(request.url).searchParams.get('placement_id');
  if (!placementId || placementId.length > 128) return reply({ error: 'invalid_placement_id' }, 422);
  const placement = await env.ADS_DB.prepare(
    "SELECT id, publisher_id, status FROM ads_placements WHERE id=?"
  ).bind(placementId).first();
  if (!placement || placement.publisher_id !== 'pub-test-001') return reply({ error: 'not_found' }, 404);
  if (placement.status !== 'approved') return reply({ error: 'placement_not_approved' }, 409);
  const campaign = await env.ADS_DB.prepare(
    "SELECT id, name, format FROM ads_campaigns WHERE status='active' ORDER BY created_at, id LIMIT 1"
  ).first();
  if (!campaign) return reply({ item: null });
  return reply({ item: { campaign_id: campaign.id, name: campaign.name, format: campaign.format, placement_id: placement.id },
    note: 'test_selection_only_no_creative_no_budget_charge_no_impression' });
}
