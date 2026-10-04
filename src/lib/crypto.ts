import { env } from "./env";

/**
 * All primitives use Web Crypto (available in Workers, Node and browsers) — no node:crypto.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}
export function fromB64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export const toB64Url = (bytes: Uint8Array) => toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(n));
  crypto.getRandomValues(out);
  return out;
}

async function aesKey(): Promise<CryptoKey> {
  const raw = fromB64(env.dataKey);
  if (raw.length !== 32) throw new Error("DATA_ENCRYPTION_KEY must be 32 random bytes, base64-encoded");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM. Output: v1:<iv>:<ciphertext||tag> (base64). */
export async function encrypt(plaintext: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(), enc.encode(plaintext));
  return `v1:${toB64(iv)}:${toB64(new Uint8Array(ct))}`;
}

export async function decrypt(payload: string): Promise<string> {
  const [v, iv, ct] = payload.split(":");
  if (v !== "v1" || !iv || !ct) throw new Error("Unrecognised ciphertext format");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, await aesKey(), fromB64(ct));
  return dec.decode(pt);
}

export async function sha256Hex(input: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(input)));
}

export async function hmacHex(secret: string, input: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(input)));
}

/** Raw IP addresses are never stored — only a keyed hash used for rate limiting. */
export async function hashIp(ip: string): Promise<string> {
  return (await hmacHex(env.ipHashSecret, `ipaddr:${ip}`)).slice(0, 32); // own domain prefix: cannot collide with hashKey()
}
/** Keyed hash for throttling by email without storing the address in the attempts table. */
export async function hashKey(kind: string, value: string): Promise<string> {
  return (await hmacHex(env.ipHashSecret, `${kind}:${value}`)).slice(0, 32);
}

export async function newShareToken(): Promise<{ token: string; hash: string }> {
  const token = toB64Url(randomBytes(32)); // 256 bits
  return { token, hash: await hashToken(token) };
}

export const hashToken = (token: string) => sha256Hex(token);

/** Constant-time string comparison. */
export function safeEqual(a: string, b: string): boolean {
  const x = enc.encode(a), y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
