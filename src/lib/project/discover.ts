import { ScanBudget } from "../ssrf/budget";
import { resolvePublicAddresses, type Resolver } from "../ssrf/dns";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { createWorkerFetcher } from "../ssrf/worker-fetch";
import { parseHtml } from "../scanner/parse";
import type { FirebaseInput, SupabaseInput } from "./system-scan";

/**
 * Tự tìm cấu hình backend công khai từ website: Supabase (URL dự án + khoá anon) và Firebase (projectId, apiKey…) vốn được nhúng sẵn
 * trong JavaScript phía trình duyệt. Chỉ đọc trang chủ và vài file JS cùng nguồn, qua bộ fetch chống SSRF đã dùng cho quét website.
 * Giá trị tìm thấy chỉ sống trong bộ nhớ của request này.
 */
export interface Discovered { site: string; host: string; supabase: SupabaseInput | null; firebase: FirebaseInput | null; scripts: number }

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const decode = (jwt: string): Record<string, unknown> | null => {
  try { const o = JSON.parse(atob(jwt.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))); return o && typeof o === "object" ? o : null; } catch { return null; }
};

export function extractBackends(text: string): { supabase: { ref: string; key: string } | null; firebase: Omit<FirebaseInput, "projectId"> & { projectId: string } | null } {
  let supabase: { ref: string; key: string } | null = null;
  const refs = [...new Set([...text.matchAll(/https:\/\/([a-z0-9]{20})\.supabase\.(?:co|in)/g)].map((m) => m[1]!))];
  for (const ref of refs) {
    let key: string | null = null;
    for (const m of text.matchAll(JWT)) { const p = decode(m[0]); if (p?.role === "anon" && (p.ref === ref || p.ref === undefined)) { key = m[0]; break; } } // service_role KHÔNG BAO GIỜ được chọn
    key ??= text.match(/\bsb_publishable_[A-Za-z0-9_-]{16,}\b/)?.[0] ?? null;
    if (key) { supabase = { ref, key }; break; }
  }

  let firebase: ReturnType<typeof extractBackends>["firebase"] = null;
  if (/AIza[0-9A-Za-z_-]{35}|firebaseapp\.com|firebaseio\.com|firebasestorage|firebasedatabase\.app/.test(text)) {
    const pick = (k: string, re: string) => text.match(new RegExp(`["']?${k}["']?\\s*:\\s*["'](${re})["']`))?.[1];
    const projectId = pick("projectId", "[a-z][a-z0-9-]{4,29}");
    if (projectId) firebase = { projectId, apiKey: pick("apiKey", "AIza[0-9A-Za-z_-]{35}"), storageBucket: pick("storageBucket", "[a-z0-9][a-z0-9._-]{2,62}"), databaseURL: pick("databaseURL", "https://[a-z0-9.-]+") };
  }
  return { supabase, firebase };
}

export class DiscoverError extends Error { constructor(readonly code: string, message: string, readonly blocked = false) { super(message); } }

export async function discoverBackend(rawUrl: string, d: { resolver: Resolver; fetchImpl?: typeof fetch; denyHosts?: string[] }): Promise<Discovered> {
  let target;
  try { target = normalizeTargetUrl(rawUrl); await resolvePublicAddresses(target.host, d.resolver); }
  catch (e) { if (e instanceof SsrfError) throw new DiscoverError(e.code, e.message, e.code !== "dns_failed"); throw e; }

  const budget = new ScanBudget(14, 12 * 1024 * 1024, 30_000);
  const f = createWorkerFetcher(budget, { resolver: d.resolver, fetchImpl: d.fetchImpl, denyHosts: d.denyHosts });
  const page = await f(target.url, { maxBytes: 1_500_000 });
  if (page.error?.blocked) throw new DiscoverError(page.error.code, page.error.message, true);
  if (!page.body || page.error) throw new DiscoverError("unreachable", "Không mở được website này. Hãy kiểm tra địa chỉ hoặc nhập thông tin thủ công.");

  let text = page.body;
  const html = parseHtml(page.body, page.finalUrl);
  const scripts = html.scripts.filter((s) => s.url && s.sameOrigin && !s.inline).map((s) => s.url!).slice(0, 12);
  const fetched = await Promise.all(scripts.map((u) => f(u, { maxBytes: 2_000_000, timeoutMs: 8_000 }).then((r) => r.body).catch(() => "")));
  text += "\n" + fetched.join("\n");
  const { supabase, firebase } = extractBackends(text);
  return {
    site: target.url, host: target.host, scripts: scripts.length,
    supabase: supabase ? { url: supabase.ref, anonKey: supabase.key } : null,
    firebase,
  };
}
