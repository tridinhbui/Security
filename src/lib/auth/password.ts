import { scryptAsync } from "@noble/hashes/scrypt.js";
import { fromB64, randomBytes, safeEqual, toB64 } from "../crypto";

/**
 * scrypt with N=2^15, r=8, p=3 (an OWASP-recommended configuration, ~180 ms). Pure JS so it runs
 * identically in Workers and Node. Parameters are stored in the hash so they can be raised later.
 */
const PARAMS = { N: 2 ** 15, r: 8, p: 3, dkLen: 32 };
const enc = new TextEncoder();

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const dk = await scryptAsync(enc.encode(password.normalize("NFKC")), salt, PARAMS);
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${toB64(salt)}$${toB64(dk)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [alg, N, r, p, salt, hash] = stored.split("$");
  if (alg !== "scrypt" || !N || !r || !p || !salt || !hash) return false;
  const params = { N: Number(N), r: Number(r), p: Number(p), dkLen: 32 };
  if (!(params.N <= 2 ** 17 && params.r <= 16 && params.p <= 8)) return false; // refuse absurd stored costs
  const dk = await scryptAsync(enc.encode(password.normalize("NFKC")), fromB64(salt), params);
  return safeEqual(toB64(dk), hash);
}

let dummy: Promise<string> | null = null;
/** Burn the same CPU as a real verification so unknown emails are not distinguishable by timing. */
export async function dummyVerify(password: string): Promise<void> {
  dummy ??= hashPassword("vibesec-dummy-password");
  await verifyPassword(password, await dummy);
}

const COMMON = new Set(["password", "password1", "password123", "1234567890", "qwertyuiop", "letmein123", "iloveyou123", "admin12345", "welcome123", "changeme123", "1q2w3e4r5t", "abcdefghij", "0123456789", "passw0rd123"]);

export function validateCredentials(email: string, password: string): { ok: true; email: string } | { ok: false; error: "invalid_email" | "weak_password"; message: string } {
  const e = email.trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)+$/.test(e)) return { ok: false, error: "invalid_email", message: "Hãy nhập một địa chỉ email hợp lệ." };
  if (password.length < 10 || password.length > 128) return { ok: false, error: "weak_password", message: "Mật khẩu phải có từ 10 đến 128 ký tự." };
  if (COMMON.has(password.toLowerCase()) || password.toLowerCase().includes(e.split("@")[0]!) && e.split("@")[0]!.length >= 4) return { ok: false, error: "weak_password", message: "Mật khẩu này quá dễ đoán. Hãy chọn mật khẩu khó đoán hơn." };
  return { ok: true, email: e };
}
