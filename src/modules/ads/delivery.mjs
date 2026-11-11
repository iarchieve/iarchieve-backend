import { authenticatePublisher } from './publisher-auth.mjs';
const reply = (data, status = 200) => Response.json(data, {
  status, headers: { 'Cache-Control': 'no-store' }
});

function legacyActor(request, env) {
  if (env.ADS_ALLOW_LEGACY_PUBLISHER_TOKEN !== 'true') return null;
  const header = /^Bearer ([a-fA-F0-9]{64})$/.exec(request.headers.get('Authorization') || '');
  const secret = env.ADS_PUBLISHER_TOKEN;
  if (!header || typeof secret !== 'string' || !/^[a-fA-F0-9]{64}$/.test(secret)) return false;
  let difference = 0;
  const a = header[1].toUpperCase();
  const b = secret.toUpperCase();
  for (let i = 0; i < 64; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0 ? { role: 'publisher', id: 'pub-test-001' } : null;
}

export async function handleAdsDelivery(request, env) {
  const actor = legacyActor(request, env) || await authenticatePublisher(request, env);
  if (!actor) return reply({ error: 'unauthorized' }, 401);
  if (!env.ADS_DB) return reply({ error: 'database_unavailable' }, 503);
  const path = new URL(request.url).pathname;
  if (path !== '/api/ads/delivery/next' || request.method !== 'GET') {
    return reply({ error: 'not_found' }, 404);
  }
  const placementId = new URL(request.url).searchParams.get('placement_id');
  if (!placementId || placementId.length > 128) return reply({ error: 'invalid_placement_id' }, 422);
  const placement = await env.ADS_DB.prepare(
    `SELECT id, publisher_id, status, format
     FROM ads_placements
     WHERE id=? AND publisher_id=?
       AND EXISTS (
         SELECT 1 FROM ads_accounts
         WHERE ads_accounts.id=ads_placements.publisher_id
           AND ads_accounts.role='publisher'
           AND ads_accounts.status='active'
       )`
  ).bind(placementId, actor.id).first();
  if (!placement || placement.publisher_id !== actor.id) return reply({ error: 'not_found' }, 404);
  if (placement.status !== 'approved') return reply({ error: 'placement_not_approved' }, 409);
  const campaign = await env.ADS_DB.prepare(
    `SELECT a.id, a.name, a.format,
       c.id AS creative_id, c.title,
       c.image_url, c.target_url
FROM ads_campaigns a
JOIN ads_creatives c ON c.campaign_id=a.id
WHERE a.status='active' AND c.status='approved' AND a.format=?
ORDER BY a.created_at, a.id, c.created_at, c.id
LIMIT 1`
  ).bind(placement.format).first();
  if (!campaign) return reply({ item: null });
  return reply({ item: { campaign_id: campaign.id, name: campaign.name, format: campaign.format, placement_id: placement.id, creative_id: campaign.creative_id, title: campaign.title, image_url: campaign.image_url, target_url: campaign.target_url },
    note: 'test_selection_only_no_creative_no_budget_charge_no_impression' });
}
