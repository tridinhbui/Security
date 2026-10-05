import { decrypt, encrypt, hashKey, safeEqual } from "../crypto";
import type { D1Like } from "../db/d1";
import * as repo from "../db/repo";
import { env } from "../env";
import { startSessionFor } from "./core";
import { buildAuthUrl, exchangeCode, GoogleAuthError, pkcePair, randomToken, verifyGoogleIdToken, type JwksFetcher } from "./google";

/** Trạng thái OAuth giữ trong một cookie HttpOnly đã MÃ HOÁ (AES-GCM): chống giả mạo, không lộ code_verifier. */
export interface OAuthState { s: string; n: string; v: string; x: string; t: number }
export const OAUTH_COOKIE = "vs_oauth";
export const OAUTH_TTL_MS = 10 * 60_000;

/** Chỉ cho chuyển hướng tới đường dẫn tương đối cùng site (chống open redirect). */
export function safeNext(raw: string | null | undefined): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\") && !/[\r\n]/.test(raw) ? raw : "/dashboard";
}

/** Redirect URI: dùng SITE_URL cố định ở production (không tin header Host), chỉ cho phép localhost khi chạy thử. */
export function redirectUriFor(requestOrigin: string): string {
  let host = "";
  try { host = new URL(requestOrigin).hostname; } catch { /* dùng siteUrl */ }
  const base = host === "localhost" || host === "127.0.0.1" ? requestOrigin : env.siteUrl;
  return `${base.replace(/\/$/, "")}/api/auth/google/callback`;
}

export async function startGoogleLogin(a: { next: string | null; requestOrigin: string }): Promise<{ location: string; cookie: string }> {
  const clientId = env.googleClientId;
  if (!clientId || !env.googleClientSecret) throw new GoogleAuthError("not_configured");
  const { verifier, challenge } = await pkcePair();
  const st: OAuthState = { s: randomToken(), n: randomToken(), v: verifier, x: safeNext(a.next), t: Date.now() };
  return {
    cookie: await encrypt(JSON.stringify(st)),
    location: buildAuthUrl({ clientId, redirectUri: redirectUriFor(a.requestOrigin), state: st.s, nonce: st.n, codeChallenge: challenge }),
  };
}

export interface FinishDeps { db: D1Like; fetchImpl?: typeof fetch; jwks?: JwksFetcher }

/** Hoàn tất đăng nhập. Ném GoogleAuthError với mã an toàn để hiển thị; không bao giờ lộ chi tiết nội bộ. */
export async function finishGoogleLogin(
  a: { code: string | null; state: string | null; error: string | null; cookie: string | undefined; requestOrigin: string; ipHash: string | null },
  d: FinishDeps,
): Promise<{ userId: string; token: string; expiresAt: string; next: string }> {
  const ipKey = a.ipHash ? await hashKey("ip", a.ipHash) : null;
  if (ipKey && (await repo.countAttempts(d.db, "oauth_fail_ip", ipKey, 15 * 60_000)) >= env.limits.oauthFailsPerIp) {
    await repo.recordEvent(d.db, { type: "auth_throttled", level: "warn", message: "oauth" });
    throw new GoogleAuthError("throttled");
  }
  const fail = async (code: ConstructorParameters<typeof GoogleAuthError>[0]): Promise<never> => {
    if (ipKey) await repo.recordAttempt(d.db, "oauth_fail_ip", ipKey);
    await repo.recordEvent(d.db, { type: "auth_login_failed", level: "warn", message: `google:${code}` });
    throw new GoogleAuthError(code);
  };

  if (a.error) return fail(a.error === "access_denied" ? "access_denied" : "token_exchange");
  if (!a.code || !a.state || !a.cookie || a.code.length > 2048) return fail("state_mismatch");

  let st: OAuthState;
  try { st = JSON.parse(await decrypt(a.cookie)) as OAuthState; } catch { return fail("state_mismatch"); }
  if (!safeEqual(st.s, a.state)) return fail("state_mismatch"); // chống CSRF đăng nhập
  if (Date.now() - st.t > OAUTH_TTL_MS || st.t > Date.now() + 60_000) return fail("state_expired");

  const clientId = env.googleClientId, clientSecret = env.googleClientSecret;
  if (!clientId || !clientSecret) return fail("not_configured");

  let claims;
  try {
    const idToken = await exchangeCode({ code: a.code, verifier: st.v, clientId, clientSecret, redirectUri: redirectUriFor(a.requestOrigin) }, d.fetchImpl);
    claims = await verifyGoogleIdToken(idToken, { clientId, nonce: st.n, jwks: d.jwks });
  } catch (e) {
    return fail(e instanceof GoogleAuthError ? e.code : "token_exchange");
  }

  const { user, created } = await repo.upsertGoogleUser(d.db, claims);
  if (user.blocked_until && user.blocked_until > new Date().toISOString()) return fail("blocked");
  await repo.recordEvent(d.db, { type: created ? "auth_signup" : "auth_login", userId: user.id, message: "google" });
  const session = await startSessionFor(d.db, user.id);
  return { userId: user.id, ...session, next: safeNext(st.x) };
}
