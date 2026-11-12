import { handlePublisherAdmin } from '../modules/ads/publisher-admin.mjs';
import { handleCredentialManagement } from '../modules/ads/credential-management.mjs';
import { handleAdsCreatives } from '../modules/ads/creatives.mjs';
import { handleAdsOperations } from '../modules/ads/operations.mjs';
import { handleAds } from '../modules/ads/api.mjs';
import { handleAdsDelivery } from '../modules/ads/delivery.mjs';
import { handleAdsDeliveryIssue } from '../modules/ads/delivery-issue.mjs';
import { handleImpressionClaim } from '../modules/ads/impression-claim.mjs';
import { handleVerificationAssessment } from '../modules/ads/verification-assess.mjs';
import { handleLoveAssessment } from '../modules/ads/love-assess.mjs';
import { handleLoveSessionIssue } from '../modules/ads/love-session-issue.mjs';
import { handleLoveLifecycle } from '../modules/ads/love-lifecycle.mjs';

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname === "/api/ads/admin/publishers" ||
        pathname.startsWith("/api/ads/admin/publishers/")) {
      try {
        return await handlePublisherAdmin(request, env);
      } catch (error) {
        console.error("Publisher admin failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }

    if (pathname === "/api/ads/publisher-credentials" ||
        pathname.startsWith("/api/ads/publisher-credentials/")) {
      try {
        return await handleCredentialManagement(request, env);
      } catch (error) {
        console.error("Credential management failure", error);
        return Response.json({ error: "internal_error" }, { status: 500 });
      }
    }

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

    if (pathname === "/api/ads/creatives" ||
        pathname.startsWith("/api/ads/creatives/")) {
      try {
        return await handleAdsCreatives(request, env);
      } catch (error) {
        console.error("Ads creatives failure", error);
        return Response.json({ error: "internal_error" }, { status: 500 });
      }
    }
    if (pathname === "/api/ads/admin/love-sessions") {
      return Response.json({ error: "direct_issuance_disabled",
        replacement: "/api/ads/admin/love-reservations" },
        { status: 410, headers: { "Cache-Control": "no-store" } });
    }
    if (pathname === "/api/ads/admin/love-reservations" ||
        /^\/api\/ads\/admin\/love-reservations\/[^/]+\/finalize$/.test(pathname)) {
      try { return await handleLoveLifecycle(request, env); }
      catch (error) {
        console.error("LOVE lifecycle failure", error);
        return Response.json({ error: "internal_error" }, { status: 500 });
      }
    }
    if (pathname === "/api/ads/verifications/love-assess") {
      try {
        return await handleLoveAssessment(request, env);
      } catch (error) {
        console.error("LOVE assessment failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }
    if (pathname === "/api/ads/verifications/assess") {
      return Response.json(
        {
          error: "legacy_verification_disabled",
          replacement: "/api/ads/verifications/love-assess"
        },
        {
          status: 410,
          headers: { "Cache-Control": "no-store" }
        }
      );
    }
    if (pathname === "/api/ads/impressions/claim") {
      try {
        return await handleImpressionClaim(request, env);
      } catch (error) {
        console.error("Impression claim failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }
    if (pathname === "/api/ads/delivery/issue") {
      try {
        return await handleAdsDeliveryIssue(request, env);
      } catch (error) {
        console.error("Delivery issuance failure", error);
        return Response.json(
          { error: "internal_error" },
          { status: 500 }
        );
      }
    }
    if (pathname.startsWith('/api/ads/delivery/')) {
      try {
        return await handleAdsDelivery(request, env);
      } catch (error) {
        console.error('Ads delivery failure', error);
        return Response.json({ error: 'internal_error' }, { status: 500 });
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
