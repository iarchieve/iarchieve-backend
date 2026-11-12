import { openProtectedProof } from "./love-proof.mjs";

const encoder = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const B64 = /^[A-Za-z0-9_-]+$/;

async function sha256(bytes) {
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(result), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

export async function evidenceDigest(proof) {
  if (typeof proof !== "string" ||
      encoder.encode(proof).length > 65536) {
    throw new Error("invalid_evidence");
  }

  return sha256(encoder.encode(proof));
}

// The envelope digest is based on a fixed, versioned field order.
// Unrecognized fields are rejected rather than silently ignored.
export async function protectedEnvelopeDigest(envelope) {
  if (!envelope || typeof envelope !== "object" ||
      Array.isArray(envelope)) {
    throw new Error("invalid_envelope");
  }

  const fields = [
    "algorithm", "ciphertext", "claim_id", "evidence_digest",
    "expires_at", "issued_at", "iv", "session_nonce",
    "verifier_id", "version"
  ];

  if (Object.keys(envelope).sort().join(",") !==
      [...fields].sort().join(",")) {
    throw new Error("invalid_envelope_fields");
  }

  if (envelope.version !== 1 ||
      envelope.algorithm !== "AES-256-GCM" ||
      typeof envelope.claim_id !== "string" ||
      !UUID.test(envelope.claim_id) ||
      typeof envelope.verifier_id !== "string" ||
      !ID.test(envelope.verifier_id) ||
      typeof envelope.evidence_digest !== "string" ||
      !HEX64.test(envelope.evidence_digest) ||
      typeof envelope.session_nonce !== "string" ||
      !HEX32.test(envelope.session_nonce) ||
      typeof envelope.issued_at !== "string" ||
      typeof envelope.expires_at !== "string" ||
      !Number.isFinite(Date.parse(envelope.issued_at)) ||
      !Number.isFinite(Date.parse(envelope.expires_at)) ||
      Date.parse(envelope.expires_at) <=
        Date.parse(envelope.issued_at) ||
      typeof envelope.iv !== "string" ||
      !B64.test(envelope.iv) ||
      typeof envelope.ciphertext !== "string" ||
      !B64.test(envelope.ciphertext)) {
    throw new Error("invalid_envelope");
  }

  const canonical = [
    "iarchieve.ads.love-envelope-digest.v1",
    ...fields.map(field => envelope[field])
  ];

  return sha256(encoder.encode(JSON.stringify(canonical)));
}

export async function verifyProtectedEvidence(
  envelope, key, session, now = Date.now()
) {
  if (!session || typeof session !== "object" ||
      session.status !== "issued" ||
      typeof session.id !== "string" ||
      !UUID.test(session.id) ||
      session.claim_id !== envelope?.claim_id ||
      session.verifier_id !== envelope?.verifier_id ||
      session.session_nonce !== envelope?.session_nonce ||
      !Number.isFinite(now)) {
    throw new Error("session_binding_mismatch");
  }

  const sessionExpiry = Date.parse(session.expires_at);

  if (!Number.isFinite(sessionExpiry) ||
      now >= sessionExpiry ||
      Date.parse(envelope.expires_at) > sessionExpiry) {
    throw new Error("session_expired_or_invalid");
  }

  const digest = await protectedEnvelopeDigest(envelope);

  if (digest !== session.envelope_digest) {
    throw new Error("envelope_digest_mismatch");
  }

  const proof = await openProtectedProof(
    envelope,
    key,
    {
      claim_id: session.claim_id,
      verifier_id: session.verifier_id,
      evidence_digest: envelope.evidence_digest
    },
    now
  );

  const actual = await evidenceDigest(proof);

  if (actual !== envelope.evidence_digest) {
    throw new Error("evidence_digest_mismatch");
  }

  return {
    session_id: session.id,
    claim_id: session.claim_id,
    verifier_id: session.verifier_id,
    envelope_digest: digest,
    evidence_digest: actual,
    envelope_verified: true,
    evidence_verified: true,
    final_verification: false,
    billable: false
  };
}