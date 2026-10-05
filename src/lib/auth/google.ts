import { randomBytes, toB64Url } from "../crypto";

/**
 * Google OAuth 2.0 (authorization code + PKCE) — phần thuần, dùng Web Crypto, không phụ thuộc framework.
 * Bí mật (client secret) chỉ xuất hiện trong exchangeCode() chạy ở Worker; không bao giờ xuống trình duyệt.
 */

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

export type GoogleErrorCode =
  | "state_mismatch" | "state_expired" | "token_exchange" | "invalid_token" | "email_unverified" | "access_denied" | "not_configured" | "throttled" | "blocked";

export class GoogleAuthError extends Error {
  constructor(public readonly code: GoogleErrorCode, message?: string) {
    super(message ?? code);
    this.name = "GoogleAuthError";
  }
}

const enc = new TextEncoder();

/** PKCE (RFC 7636): verifier ngẫu nhiên 256 bit, challenge = BASE64URL(SHA-256(verifier)). */
export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = toB64Url(randomBytes(32));
  return { verifier, challenge: await challengeFor(verifier) };
}
export async function challengeFor(verifier: string): Promise<string> {
  return toB64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(verifier))));
}
export const randomToken = () => toB64Url(randomBytes(24));

export function buildAuthUrl(a: { clientId: string; redirectUri: string; state: string; nonce: string; codeChallenge: string }): string {
  const u = new URL(GOOGLE_AUTH_URL);
  u.search = new URLSearchParams({
    client_id: a.clientId, redirect_uri: a.redirectUri, response_type: "code", scope: "openid email profile",
    state: a.state, nonce: a.nonce, code_challenge: a.codeChallenge, code_challenge_method: "S256",
    access_type: "online", prompt: "select_account", include_granted_scopes: "false",
  }).toString();
  return u.toString();
}

export async function exchangeCode(a: { code: string; verifier: string; clientId: string; clientSecret: string; redirectUri: string }, fetchImpl: typeof fetch = fetch): Promise<string> {
  let res: Response;
  try {
    res = await fetchImpl(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ code: a.code, code_verifier: a.verifier, client_id: a.clientId, client_secret: a.clientSecret, redirect_uri: a.redirectUri, grant_type: "authorization_code" }),
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new GoogleAuthError("token_exchange");
  }
  if (!res.ok) throw new GoogleAuthError("token_exchange"); // không chuyển tiếp nội dung lỗi của Google
  const body = (await res.json().catch(() => null)) as { id_token?: unknown } | null;
  if (!body || typeof body.id_token !== "string") throw new GoogleAuthError("token_exchange");
  return body.id_token;
}

// ------------------------------------------------------------------ xác minh id_token

interface Jwk extends JsonWebKey { kid?: string }
export type JwksFetcher = (forceRefresh: boolean) => Promise<Jwk[]>;

let jwksCache: { at: number; keys: Jwk[] } | null = null;
/** Bộ nhớ đệm khoá công khai của Google (cấu hình chung, không phải trạng thái theo request). */
export const defaultJwks: JwksFetcher = async (force) => {
  if (!force && jwksCache && Date.now() - jwksCache.at < 3_600_000) return jwksCache.keys;
  const res = await fetch(GOOGLE_JWKS_URL, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new GoogleAuthError("invalid_token");
  const keys = ((await res.json()) as { keys?: Jwk[] }).keys ?? [];
  jwksCache = { at: Date.now(), keys };
  return keys;
};

function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const parseJson = (b: Uint8Array) => { try { return JSON.parse(new TextDecoder().decode(b)) as Record<string, unknown>; } catch { return null; } };

export interface GoogleClaims { sub: string; email: string; name: string | null; picture: string | null }

export async function verifyGoogleIdToken(token: string, o: { clientId: string; nonce: string; jwks?: JwksFetcher; nowSec?: number }): Promise<GoogleClaims> {
  const bad = () => new GoogleAuthError("invalid_token");
  if (token.length > 4096) throw bad();
  const parts = token.split(".");
  if (parts.length !== 3) throw bad();
  const header = parseJson(b64urlToBytes(parts[0]!));
  const payload = parseJson(b64urlToBytes(parts[1]!));
  if (!header || !payload) throw bad();
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw bad(); // chặn alg=none và tấn công nhầm thuật toán (HS256)

  const getKeys = o.jwks ?? defaultJwks;
  let jwk = (await getKeys(false)).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await getKeys(true)).find((k) => k.kid === header.kid); // khoá có thể vừa được xoay
  if (!jwk || jwk.kty !== "RSA") throw bad();

  const key = await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]!), enc.encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw bad();

  const now = o.nowSec ?? Math.floor(Date.now() / 1000);
  const aud = payload.aud;
  if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") throw bad();
  if (!(aud === o.clientId || (Array.isArray(aud) && aud.includes(o.clientId)))) throw bad();
  if (typeof payload.exp !== "number" || payload.exp + 60 < now) throw bad();
  if (typeof payload.iat === "number" && payload.iat > now + 120) throw bad();
  if (typeof payload.nonce !== "string" || payload.nonce !== o.nonce) throw bad();
  if (typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 255) throw bad();
  if (typeof payload.email !== "string" || payload.email.length > 254) throw bad();
  if (payload.email_verified !== true) throw new GoogleAuthError("email_unverified");

  const str = (v: unknown, max: number) => (typeof v === "string" && v.length <= max ? v : null);
  const picture = str(payload.picture, 500);
  return { sub: payload.sub, email: payload.email.toLowerCase(), name: str(payload.name, 120), picture: picture && /^https:\/\//.test(picture) ? picture : null };
}
