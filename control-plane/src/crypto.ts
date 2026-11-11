// Tokens, policy signing and key wrapping, all on WebCrypto.

const b64 = (bytes: ArrayBuffer | Uint8Array): string =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (text: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const hex = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256Hex(data: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

/** A new bearer token: 32 random bytes, with a prefix that says what it is for. */
export function newToken(kind: "admin" | "agent"): string {
  const random = b64(crypto.getRandomValues(new Uint8Array(32)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return `sst_${kind}_${random}`;
}

async function wrappingKey(secret: string): Promise<CryptoKey> {
  const raw = unb64(secret);
  if (raw.length !== 32) throw new Error("KEY_ENCRYPTION_KEY must be 32 bytes, base64-encoded");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export interface TenantKey {
  keyId: string;
  /** Raw 32-byte public key, base64: what a connector is told to trust. */
  publicKey: string;
  /** PKCS#8 private key, AES-GCM encrypted: "<iv>.<ciphertext>", both base64. */
  wrappedPrivateKey: string;
}

export async function newTenantKey(kek: string): Promise<TenantKey> {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const publicRaw = (await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer;
  const pkcs8 = (await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer;
  return {
    // Same definition as safestream_enterprise.policy.key_id.
    keyId: hex(await crypto.subtle.digest("SHA-256", publicRaw)).slice(0, 16),
    publicKey: b64(publicRaw),
    wrappedPrivateKey: await wrap(pkcs8, kek),
  };
}

export async function wrap(pkcs8: ArrayBuffer, kek: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await wrappingKey(kek), pkcs8);
  return `${b64(iv)}.${b64(sealed)}`;
}

async function unwrap(wrapped: string, kek: string): Promise<CryptoKey> {
  const [iv, sealed] = wrapped.split(".");
  const pkcs8 = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(iv!) },
    await wrappingKey(kek),
    unb64(sealed!),
  );
  return crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
}

/**
 * A signed policy bundle, byte-compatible with safestream_enterprise.policy:
 * the connector verifies exactly these bytes.
 */
export async function signBundle(
  key: { keyId: string; wrappedPrivateKey: string },
  kek: string,
  payload: { tenant: string; version: number; issued_at: string; field_rules: unknown },
): Promise<string> {
  const body = new TextEncoder().encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign("Ed25519", await unwrap(key.wrappedPrivateKey, kek), body);
  return (
    JSON.stringify(
      {
        schema: "safestream.policy/v1",
        payload: b64(body),
        signatures: [{ key_id: key.keyId, algorithm: "ed25519", signature: b64(signature) }],
      },
      null,
      2,
    ) + "\n"
  );
}
