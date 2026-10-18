import { describe, expect, it } from "vitest";
import { runQuickScan, type QuickResult } from "../quick";
import type { Resolver } from "@/lib/ssrf/dns";

/**
 * BENCHMARK THEO NỀN TẢNG (giả lập, KHÔNG phải quét website thật): 16 cấu hình đại diện cho Cloudflare, Vercel, Netlify, CDN,
 * DNS, HTTPS và tường lửa (WAF), chạy qua TOÀN BỘ luồng quét nhanh (thu thập → luật → chấm điểm → phạm vi) với phản hồi HTTP và DNS
 * giả lập. Mỗi cấu hình có “đáp án” viết tay: những gì PHẢI bị báo và những gì KHÔNG được báo.
 */
const resolver: Resolver = async () => [{ address: "104.16.0.1", family: 4 }];
const HTML = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Shop</title><script src="/app.js"></script></head><body><h1>Xin chào</h1></body></html>`;
const STRONG: Record<string, string> = {
  "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()", "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "cache-control": "private, no-cache",
};
type Dns = (Partial<Record<"TXT" | "_dmarc" | "_mta-sts" | "CAA" | "MX", string[]>> & { dnssec?: boolean }) | "fail";
interface Scenario { host: string; https?: (u: string) => Response | null; http?: "redirect" | "serve" | "refuse"; dns?: Dns }

function fetchFor(s: Scenario): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) {
      if (s.dns === "fail") return new Response("err", { status: 503 });
      const q = new URL(url), name = q.searchParams.get("name")!, type = Number(q.searchParams.get("type"));
      const d = s.dns ?? {};
      const pick = name.startsWith("_dmarc.") ? d._dmarc : name.startsWith("_mta-sts.") ? d["_mta-sts"] : type === 16 ? d.TXT : type === 257 ? d.CAA : type === 15 ? d.MX : undefined;
      return Response.json({ Status: 0, AD: d.dnssec === true, Answer: (pick ?? []).map((data) => ({ type, data: type === 16 ? `"${data}"` : data })) });
    }
    const u = new URL(url);
    if (u.hostname !== s.host) return new Response("", { status: 404 });
    if (u.protocol === "http:") {
      if (s.http === "refuse") throw new TypeError("connect ECONNREFUSED");
      if (s.http === "serve") return new Response(HTML, { headers: { "content-type": "text/html" } });
      return new Response(null, { status: 301, headers: { location: `https://${s.host}${u.pathname}` } });
    }
    const r = s.https?.(u.pathname) ?? null;
    if (r) return r;
    if (u.pathname === "/") return new Response(HTML, { headers: STRONG });
    if (init?.method === "OPTIONS") return new Response(null, { status: 204 });
    return new Response("<html><h1>404</h1></html>", { status: 404, headers: STRONG });
  }) as typeof fetch;
}
const scan = (s: Scenario) => runQuickScan(s.host, { resolver, fetchImpl: fetchFor(s) });
const issues = (r: QuickResult) => r.items.filter((i) => i.status === "fail" || i.status === "warning");
const has = (r: QuickResult, rule: string, statuses: string[] = ["fail", "warning"]) => r.items.some((i) => i.tech?.ruleId === rule && statuses.includes(i.status));
const page = (headers: Record<string, string>, body = HTML, status = 200) => (p: string) => (p === "/" ? new Response(body, { status, headers }) : null);
const GOOD_DNS: Dns = { TXT: ["v=spf1 include:_spf.google.com -all"], _dmarc: ["v=DMARC1; p=reject; rua=mailto:d@shop.vn"], "_mta-sts": ["v=STSv1; id=1"], CAA: ['0 issue "letsencrypt.org"'], MX: ["10 mx.shop.vn."], dnssec: true };

describe("benchmark theo nền tảng (giả lập toàn bộ luồng quét nhanh)", () => {
  it("1. Cloudflare proxy, cấu hình chặt: cookie __cf_bm + cache HIT không bị coi là rò rỉ phiên; không hạng A vì quét nhanh", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: page({ ...STRONG, server: "cloudflare", "cf-ray": "8a1-SIN", "cf-cache-status": "HIT", age: "30", "set-cookie": "__cf_bm=x; Path=/; Secure; HttpOnly; SameSite=None" }) });
    expect(has(r, "adv.shared-cache-leak")).toBe(false);
    expect(has(r, "headers.cache-policy")).toBe(false);
    expect(has(r, "config.server-disclosure")).toBe(false); // “cloudflare” không kèm phiên bản
    expect(r.grade).not.toBe("A");
    expect(r.coverage!.areas.find((a) => a.id === "certificate")!.state).toBe("out_of_scope");
  });
  it("2. Cloudflare trang thử thách “Just a moment…” (403) → không chấm điểm", async () => {
    await expect(scan({ host: "shop.vn", https: page({ "content-type": "text/html", "cf-mitigated": "challenge" }, "<html><title>Just a moment...</title></html>", 403) })).rejects.toMatchObject({ code: "blocked_page" });
  });
  it("3. Vercel *.vercel.app mặc định (không header bảo mật): DNS/email là ‘không áp dụng’, header thiếu vẫn bị báo", async () => {
    const r = await scan({ host: "myshop.vercel.app", https: page({ "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=63072000", "x-vercel-id": "sin1::abc", server: "Vercel" }) });
    expect(r.items.find((i) => i.group === "dns")!.status).toBe("not_applicable");
    expect(has(r, "config.dns-email-security")).toBe(false);
    expect(has(r, "headers.csp")).toBe(true);
    expect(has(r, "headers.frame-protection")).toBe(true);
    expect(has(r, "tls.hsts-preload")).toBe(false); // tên miền con của nền tảng: không tự đăng ký preload được
  });
  it("4. Netlify *.netlify.app với _headers chặt: không có lỗi nào quy cho chủ website", async () => {
    const r = await scan({ host: "myshop.netlify.app", https: page({ ...STRONG, server: "Netlify", "x-nf-request-id": "01H" }) });
    expect(issues(r).filter((i) => i.group === "dns")).toEqual([]);
    expect(r.counts.not_applicable).toBeGreaterThan(0);
  });
  it("5. Tên miền riêng, SPF ~all + DMARC p=none: SPF đạt ở cả hai luật, DMARC p=none bị báo", async () => {
    const r = await scan({ host: "shop.vn", dns: { ...GOOD_DNS as object, TXT: ["v=spf1 include:_spf.google.com ~all"], _dmarc: ["v=DMARC1; p=none"] } });
    expect(r.items.filter((i) => /spf/i.test(i.id) && (i.status === "fail" || i.status === "warning"))).toEqual([]);
    expect(r.items.some((i) => i.id.includes("dmarc") && i.status !== "pass")).toBe(true);
  });
  it("6. DNS (DoH) lỗi hoàn toàn: không bịa lỗi DNS, nhóm DNS ‘chưa kiểm tra được’ và có ghi chú phạm vi", async () => {
    const r = await scan({ host: "shop.vn", dns: "fail" });
    expect(has(r, "config.dns-email-security")).toBe(false);
    expect(r.coverage!.areas.find((a) => a.id === "dns")!.state).toBe("unknown");
    expect((r.gaps ?? []).join(" ")).toMatch(/DNS/);
  });
  it("7. Chỉ có HTTP (cổng 443 từ chối) → không chấm điểm, hướng dẫn bật HTTPS", async () => {
    await expect(scan({ host: "shop.vn", http: "serve", https: () => { throw new TypeError("ECONNREFUSED"); } })).rejects.toMatchObject({ code: "https_unavailable" });
  });
  it("8. Không kết nối được → “chưa quét được”, không phải 0/F", async () => {
    await expect(scan({ host: "shop.vn", http: "refuse", https: () => { throw new TypeError("ECONNREFUSED"); } })).rejects.toMatchObject({ code: "unreachable" });
  });
  it("9. Đuôi .dev không chuyển hướng HTTP: ‘tham khảo’, không trừ điểm", async () => {
    const r = await scan({ host: "shop.dev", http: "serve", dns: GOOD_DNS });
    expect(has(r, "tls.http-to-https-redirect")).toBe(false);
    expect(r.items.some((i) => i.tech?.ruleId === "tls.http-to-https-redirect" && i.status === "info")).toBe(true);
  });
  it("10. Đuôi .com không chuyển hướng HTTP: lỗi thật", async () => {
    const r = await scan({ host: "shop.com", http: "serve", dns: GOOD_DNS });
    expect(has(r, "tls.http-to-https-redirect")).toBe(true);
  });
  it("11. Hai lớp proxy cùng thêm header (X-Frame-Options lặp): không báo sai", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: page({ ...STRONG, "x-frame-options": "SAMEORIGIN, SAMEORIGIN", "x-content-type-options": "nosniff, nosniff" }) });
    expect(has(r, "headers.broken")).toBe(false);
    expect(has(r, "headers.frame-protection")).toBe(false);
  });
  it("12. CSP “strict” (nonce + strict-dynamic + dự phòng 'unsafe-inline' https:): không bị báo yếu", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: page({ ...STRONG, "content-security-policy": "script-src 'nonce-r4nd' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" }) });
    expect(has(r, "headers.csp")).toBe(false);
    expect(has(r, "adv.csp-analysis")).toBe(false);
  });
  it("13. CSP 'unsafe-inline' không nonce: báo, và chỉ chiếm MỘT vị trí trừ điểm", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: page({ ...STRONG, "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" }) });
    const csp = r.items.filter((i) => i.group === "csp" && i.status === "fail");
    expect(csp.length).toBe(2);
    expect(csp.filter((i) => (i.tech?.penalty ?? 0) > 0)).toHaveLength(1);
  });
  it("14. Cookie phiên thiếu cờ trên tên miền riêng: báo", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: page({ ...STRONG, "set-cookie": "sessionid=abc; Path=/" }) });
    expect(has(r, "cookies.flags")).toBe(true);
  });
  it("15. Không có cookie nào: ‘không áp dụng’, không phải ‘đạt’", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS });
    expect(r.items.find((i) => i.tech?.ruleId === "cookies.flags")!.status).toBe("not_applicable");
  });
  it("16. Website chuẩn trên tên miền riêng: không có lỗi nào; điểm ≤ 89 (quét nhanh không bao giờ hạng A)", async () => {
    const r = await scan({ host: "shop.vn", dns: GOOD_DNS, https: (p) => (p === "/.well-known/security.txt" ? new Response("Contact: mailto:s@shop.vn\nExpires: 2099-01-01T00:00:00Z\n", { headers: { "content-type": "text/plain" } }) : null) });
    expect(issues(r).map((i) => `${i.id} ${i.text}`)).toEqual([]);
    expect(r.score).toBeLessThanOrEqual(89);
    expect(r.grade).toBe("B");
  });
});
