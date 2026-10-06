import { decrypt, encrypt, randomBytes, safeEqual, toB64Url } from "../crypto";
import { env } from "../env";

/**
 * "Kết nối GitHub" cho Quét mã nguồn. Token KHÔNG được lưu trong database: chỉ nằm trong một cookie HttpOnly đã mã hoá, sống 1 giờ,
 * dùng để liệt kê repo và tải mã nguồn cho lượt quét. Ngắt kết nối = xoá cookie. GitHub OAuth không có quyền "chỉ đọc" cho repo riêng tư,
 * nên phạm vi `repo` được dùng khi người dùng chủ động kết nối; chúng tôi chỉ đọc.
 */
export const STATE_COOKIE = "vs_gh_state";
export const TOKEN_COOKIE = "vs_gh_token";
export const STATE_TTL_S = 600;
export const TOKEN_TTL_S = 3600;

export function redirectUri(requestOrigin: string): string {
  let host = "";
  try { host = new URL(requestOrigin).hostname; } catch { /* dùng siteUrl */ }
  const base = host === "localhost" || host === "127.0.0.1" ? requestOrigin : env.siteUrl;
  return `${base.replace(/\/$/, "")}/api/github/callback`;
}

export async function startConnect(requestOrigin: string): Promise<{ location: string; cookie: string } | null> {
  const id = env.githubClientId;
  if (!id || !env.githubClientSecret) return null;
  const state = toB64Url(randomBytes(24));
  const q = new URLSearchParams({ client_id: id, redirect_uri: redirectUri(requestOrigin), scope: "repo", state, allow_signup: "false" });
  return { location: `https://github.com/login/oauth/authorize?${q}`, cookie: await encrypt(JSON.stringify({ s: state, t: Date.now() })) };
}

export async function finishConnect(a: { code: string | null; state: string | null; cookie: string | undefined; requestOrigin: string }, f: typeof fetch = fetch): Promise<string | null> {
  const id = env.githubClientId, secret = env.githubClientSecret;
  if (!id || !secret || !a.code || !a.state || !a.cookie || a.code.length > 512) return null;
  try {
    const st = JSON.parse(await decrypt(a.cookie)) as { s: string; t: number };
    if (!safeEqual(st.s, a.state) || Date.now() - st.t > STATE_TTL_S * 1000) return null;
  } catch { return null; }
  const res = await f("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { Accept: "application/json", "content-type": "application/json", "User-Agent": "VibeSec-Scanner" },
    body: JSON.stringify({ client_id: id, client_secret: secret, code: a.code, redirect_uri: redirectUri(a.requestOrigin) }), signal: AbortSignal.timeout(10_000),
  }).catch(() => null);
  const j = (await res?.json().catch(() => null)) as { access_token?: string } | null;
  return j?.access_token && /^[A-Za-z0-9_-]{20,255}$/.test(j.access_token) ? j.access_token : null;
}

export const sealToken = (t: string) => encrypt(t);
export async function openToken(cookie: string | undefined): Promise<string | null> {
  if (!cookie) return null;
  try { return await decrypt(cookie); } catch { return null; }
}

export interface RepoOption { name: string; private: boolean; pushedAt: string | null }
export async function listRepos(token: string, f: typeof fetch = fetch): Promise<RepoOption[] | null> {
  const res = await f("https://api.github.com/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member", {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "VibeSec-Scanner", "X-GitHub-Api-Version": "2022-11-28" }, signal: AbortSignal.timeout(10_000),
  }).catch(() => null);
  if (!res?.ok) return null;
  const j = (await res.json().catch(() => null)) as { full_name: string; private: boolean; pushed_at: string | null }[] | null;
  return Array.isArray(j) ? j.map((r) => ({ name: r.full_name, private: r.private, pushedAt: r.pushed_at })) : null;
}
