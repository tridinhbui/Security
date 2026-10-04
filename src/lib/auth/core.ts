import { hashKey, randomBytes, sha256Hex, toB64Url } from "../crypto";
import type { D1Like } from "../db/d1";
import { isoIn } from "../db/d1";
import * as repo from "../db/repo";
import { env } from "../env";
import { dummyVerify, hashPassword, validateCredentials, verifyPassword } from "./password";

export const SESSION_TTL_MS = 30 * 86_400_000;
const REFRESH_WHEN_LEFT_MS = 15 * 86_400_000;
const FAIL_WINDOW_MS = 15 * 60_000;

export type AuthResult =
  | { ok: true; userId: string; token: string; expiresAt: string }
  | { ok: false; status: 400 | 401 | 409 | 429; error: string; message: string };

async function startSession(db: D1Like, userId: string) {
  const token = toB64Url(randomBytes(32)); // 256-bit; only its hash is stored
  const expiresAt = isoIn(SESSION_TTL_MS);
  await repo.insertSession(db, await sha256Hex(token), userId, expiresAt);
  return { token, expiresAt };
}

export async function signup(db: D1Like, a: { email: string; password: string; ipHash: string | null }): Promise<AuthResult> {
  const v = validateCredentials(a.email, a.password);
  if (!v.ok) return { ok: false, status: 400, error: v.error, message: v.message };
  const ipKey = a.ipHash ? await hashKey("ip", a.ipHash) : null;
  if (ipKey && (await repo.countAttempts(db, "signup_ip", ipKey, 3_600_000)) >= env.limits.signupsPerIpPerHour) {
    await repo.recordEvent(db, { type: "auth_throttled", level: "warn", message: "signup", meta: { kind: "signup_ip" } });
    return { ok: false, status: 429, error: "throttled", message: "Có quá nhiều lượt đăng ký từ mạng của bạn. Vui lòng thử lại sau." };
  }
  const created = await repo.createUser(db, v.email, await hashPassword(a.password));
  if (!created.ok) return { ok: false, status: 409, error: "exists", message: "Đã có tài khoản sử dụng email này." };
  if (ipKey) await repo.recordAttempt(db, "signup_ip", ipKey);
  await repo.recordEvent(db, { type: "auth_signup", userId: created.id });
  return { ok: true, userId: created.id, ...(await startSession(db, created.id)) };
}

export async function login(db: D1Like, a: { email: string; password: string; ipHash: string | null }): Promise<AuthResult> {
  const email = a.email.trim().toLowerCase();
  const emailKey = await hashKey("email", email);
  const ipKey = a.ipHash ? await hashKey("ip", a.ipHash) : null;

  const [byEmail, byIp] = await Promise.all([
    repo.countAttempts(db, "login_fail_email", emailKey, FAIL_WINDOW_MS),
    ipKey ? repo.countAttempts(db, "login_fail_ip", ipKey, FAIL_WINDOW_MS) : Promise.resolve(0),
  ]);
  if (byEmail >= env.limits.loginFailsPerEmail || byIp >= env.limits.loginFailsPerIp) {
    await repo.recordEvent(db, { type: "auth_throttled", level: "warn", message: "login", meta: { by_email: byEmail >= env.limits.loginFailsPerEmail, by_ip: byIp >= env.limits.loginFailsPerIp } });
    return { ok: false, status: 429, error: "throttled", message: "Bạn đã thử sai quá nhiều lần. Vui lòng chờ 15 phút rồi thử lại." };
  }

  const user = await repo.getUserByEmail(db, email);
  const ok = user ? await verifyPassword(a.password, user.password_hash) : (await dummyVerify(a.password), false);
  if (!user || !ok) {
    await repo.recordAttempt(db, "login_fail_email", emailKey);
    if (ipKey) await repo.recordAttempt(db, "login_fail_ip", ipKey);
    await repo.recordEvent(db, { type: "auth_login_failed", level: "warn", userId: user?.id ?? null });
    return { ok: false, status: 401, error: "invalid_credentials", message: "Email hoặc mật khẩu không đúng." }; // same message for unknown email
  }
  await repo.clearAttempts(db, "login_fail_email", emailKey);
  await repo.recordEvent(db, { type: "auth_login", userId: user.id });
  return { ok: true, userId: user.id, ...(await startSession(db, user.id)) };
}

/** Resolve a session cookie value to a user, sliding the expiry forward when it is half used. */
export async function resolveSession(db: D1Like, token: string | undefined | null) {
  if (!token || token.length < 32 || token.length > 128) return null;
  const idHash = await sha256Hex(token);
  const row = await repo.getSessionUser(db, idHash);
  if (!row) return null;
  if (Date.parse(row.session_expires) - Date.now() < REFRESH_WHEN_LEFT_MS) await repo.extendSession(db, idHash, isoIn(SESSION_TTL_MS));
  return { id: row.id, email: row.email, retention_days: row.retention_days };
}

export async function logout(db: D1Like, token: string | undefined | null) {
  if (token) await repo.deleteSession(db, await sha256Hex(token));
}
