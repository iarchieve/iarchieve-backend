import { handleAdsOperations } from '../modules/ads/operations.mjs';
import { handleAds } from '../modules/ads/api.mjs';
import { buildReportDraft } from '../modules/reports/build-draft.mjs';

const maxBodyBytes = 1024 * 1024;

async function readReportInput(request) {
  const reader = request.body?.getReader();
  if (!reader) throw new SyntaxError('Missing JSON body');
  const decoder = new TextDecoder();
  let bytes = 0;
  let json = '';
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBodyBytes) {
        await reader.cancel();
        throw new RangeError('Body exceeds 1 MiB');
      }
      json += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(json + decoder.decode());
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (
      pathname === "/api/ads/audit" ||
      /^\/api\/ads\/(campaigns|placements)\/[^/]+$/.test(pathname)
    ) {
      try {
        return await handleAdsOperations(request, env);
      } catch (error) {
        console.error("Ads operations failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }
    if (pathname.startsWith('/api/ads/')) {
      try {
        return await handleAds(request, env);
      } catch (error) {
        console.error('Ads API failure', error);
        return Response.json(
          { error: 'internal_error' },
          { status: 500 }
        );
      }
    }
    if (pathname === '/health') {
      if (request.method !== 'GET') {
        return new Response(null, { status: 405, headers: { Allow: 'GET' } });
      }
      return Response.json({ status: 'ok', service: 'iarchieve-backend' });
    }

    if (pathname !== '/api/reports/draft') {
      return Response.json({ error: 'not_found' }, { status: 404 });
    }
    if (request.method !== 'POST') {
      return new Response(null, { status: 405, headers: { Allow: 'POST' } });
    }

    let input;
    try {
      input = await readReportInput(request);
    } catch (error) {
      if (error instanceof RangeError) {
        return Response.json({ error: 'body_too_large' }, { status: 413 });
      }
      return Response.json({ error: 'invalid_json' }, { status: 400 });
    }

    try {
      return Response.json(buildReportDraft(input));
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      return Response.json({ error: 'invalid_report_input' }, { status: 422 });
    }
  },
};
