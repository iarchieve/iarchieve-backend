const encoder = new TextEncoder();
const decoder = new TextDecoder();

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{64}$/;
const VERIFIER = /^[A-Za-z0-9_-]{1,128}$/;

const base64url = bytes =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

const fromBase64url = value => {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("invalid_encoding");
  }
  const text = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(text + "=".repeat((4 - text.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
};

const metadata = envelope => [
  "iarchieve.ads.love-proof.v1",
  envelope.claim_id,
  envelope.verifier_id,
  envelope.evidence_digest,
  envelope.session_nonce,
  envelope.issued_at,
  envelope.expires_at
];

function validateMetadata(value) {
  if (
    !value ||
    value.version !== 1 ||
    !UUID.test(value.claim_id || "") ||
    !VERIFIER.test(value.verifier_id || "") ||
    !HEX.test(value.evidence_digest || "") ||
    !/^[0-9a-f]{32}$/.test(value.session_nonce || "") ||
    !Number.isFinite(Date.parse(value.issued_at)) ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    Date.parse(value.expires_at) <= Date.parse(value.issued_at)
  ) {
    throw new Error("invalid_metadata");
  }
}

async function importAesKey(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 32) {
    throw new Error("invalid_key");
  }
  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

export function generateProofKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function createProtectedProof(input, keyBytes) {
  const now = Date.now();
  const envelope = {
    version: 1,
    claim_id: input.claim_id,
    verifier_id: input.verifier_id,
    evidence_digest: input.evidence_digest,
    session_nonce: input.session_nonce ?? Array.from(
      crypto.getRandomValues(new Uint8Array(16)),
      byte => byte.toString(16).padStart(2, "0")
    ).join(""),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 300000).toISOString()
  };

  validateMetadata(envelope);

  if (
    typeof input.proof !== "string" ||
    encoder.encode(input.proof).length > 65536
  ) {
    throw new Error("invalid_proof");
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(JSON.stringify(metadata(envelope)));
  const key = await importAesKey(keyBytes);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    encoder.encode(input.proof)
  );

  return {
    ...envelope,
    algorithm: "AES-256-GCM",
    iv: base64url(iv),
    ciphertext: base64url(new Uint8Array(encrypted))
  };
}

export async function openProtectedProof(
  envelope, keyBytes, expected, now = Date.now()
) {
  validateMetadata(envelope);

  if (
    envelope.algorithm !== "AES-256-GCM" ||
    envelope.claim_id !== expected.claim_id ||
    envelope.verifier_id !== expected.verifier_id ||
    envelope.evidence_digest !== expected.evidence_digest
  ) {
    throw new Error("love_binding_mismatch");
  }

  if (
    !Number.isFinite(now) ||
    now < Date.parse(envelope.issued_at) ||
    now >= Date.parse(envelope.expires_at)
  ) {
    throw new Error("session_expired_or_invalid");
  }

  const iv = fromBase64url(envelope.iv);
  const ciphertext = fromBase64url(envelope.ciphertext);

  if (iv.length !== 12 || ciphertext.length < 16) {
    throw new Error("invalid_ciphertext");
  }

  const aad = encoder.encode(JSON.stringify(metadata(envelope)));
  const key = await importAesKey(keyBytes);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    ciphertext
  );

  return decoder.decode(plain);
}