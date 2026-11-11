import { handleAdsOperations } from '../modules/ads/operations.mjs';
import { handleAds } from '../modules/ads/api.mjs';

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

    if (pathname.startsWith("/api/ads/")) {
      try {
        return await handleAds(request, env);
      } catch (error) {
        console.error("Ads API failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }

    if (pathname === "/health") {
      if (request.method !== "GET") {
        return new Response(null, {
          status: 405,
          headers: { Allow: "GET" }
        });
      }

      return Response.json({
        status: "ok",
        service: "iarchieve-backend"
      });
    }

    return Response.json(
      { error: "not_found" },
      { status: 404 }
    );
  }
};