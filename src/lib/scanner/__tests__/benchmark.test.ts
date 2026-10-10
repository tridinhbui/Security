import { describe, expect, it } from "vitest";
import type { Resolver } from "@/lib/ssrf/dns";
import { runQuickScan } from "../quick";

/**
 * TẬP ĐỐI CHIẾU (benchmark): các website giả lập có ĐÁP ÁN BIẾT TRƯỚC, chạy qua bộ quét nhanh thật từ đầu đến cuối
 * (bộ tải an toàn → thu thập → phân tích HTML/header/DNS → luật → chấm điểm). Mỗi site mang đúng một lỗi đã định.
 * Đo: bắt đúng (TP), bỏ sót (FN), báo nhầm (FP). Đáp án (`expect`) được viết từ chuẩn bảo mật, KHÔNG sao chép từ kết quả của công cụ.
 * Giới hạn: không bao phủ các luật cần TLS thật (xem README); site chạy trên bộ tải giả lập, không phải Internet.
 */
const HOST = "bench-site.com";
const GOOD_HEADERS: Record<string, string> = {
  "content-type": "text/html; charset=utf-8",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()", "cache-control": "private, no-cache",
  "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "cross-origin-embedder-policy": "require-corp",
};
const GOOD_BODY = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Site</title><script src="/app.js"></script></head><body><h1>Xin chào</h1><a href="/about">about</a></body></html>`;
const SECURITY_TXT = "Contact: mailto:security@bench-site.com\nExpires: 2099-01-01T00:00:00Z\n";

interface Site {
  name: string;
  headers?: Record<string, string | null>; // null = xoá header
  body?: string;
  cookies?: string[];
  notFound?: string;
  httpNoRedirect?: boolean;
  securityTxt?: boolean;
  corsReflect?: boolean;
  dmarc?: string | null;
  /** SPA: mọi đường dẫn không có đều trả 200 + HTML (bẫy báo nhầm cho robots/sitemap/security.txt). */
  spa?: boolean;
  /** Các luật PHẢI báo lỗi hoặc cảnh báo — và CHỈ các luật này. */
  expect: string[];
}

const SITES: Site[] = [
  { name: "golden (cấu hình chuẩn)", expect: [] },
  { name: "thiếu HSTS", headers: { "strict-transport-security": null }, expect: ["tls.hsts"] },
  { name: "thiếu CSP", headers: { "content-security-policy": null }, expect: ["headers.csp"] },
  { name: "CSP yếu (unsafe-inline + *)", headers: { "content-security-policy": "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'" }, expect: ["headers.csp", "adv.csp-analysis"] },
  { name: "thiếu X-Frame-Options và frame-ancestors", headers: { "x-frame-options": null, "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'" }, expect: ["headers.frame-protection"] /* chỉ MỘT luật sở hữu lỗi này */ },
  { name: "thiếu nosniff", headers: { "x-content-type-options": null }, expect: ["headers.x-content-type-options"] },
  { name: "thiếu Referrer-Policy", headers: { "referrer-policy": null }, expect: ["privacy.referrer-policy"] },
  // Thiếu Permissions-Policy là GHI CHÚ (không trừ điểm) theo chính sách hiện tại: không nằm trong tập lỗi.
  { name: "thiếu Permissions-Policy (chỉ ghi chú, không phải lỗi)", headers: { "permissions-policy": null }, expect: [] },
  { name: "cookie phiên thiếu cờ", cookies: ["session=abc123; Path=/"], expect: ["cookies.flags", "cookies.prefix"] },
  { name: "cookie phiên đầy đủ cờ", cookies: ["__Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"], expect: [] },
  { name: "CORS phản chiếu origin + credentials", corsReflect: true, expect: ["browser.cors"] },
  { name: "ảnh tải qua http:// (mixed content)", body: GOOD_BODY.replace("<h1>", '<img src="http://cdn.bench-site.com/a.png"><h1>'), expect: ["browser.mixed-content"] },
  { name: "HTTP không chuyển hướng sang HTTPS", httpNoRedirect: true, expect: ["tls.http-to-https-redirect"] },
  { name: "lộ phiên server + X-Powered-By", headers: { server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.2.34" }, expect: ["config.server-disclosure"] },
  { name: "trang 404 lộ stack trace", notFound: "<pre>Traceback (most recent call last):\n  File \"/srv/app/main.py\", line 10, in <module></pre>", expect: ["exposure.error-page-disclosure"] },
  { name: "ghi chú HTML lộ thông tin", body: GOOD_BODY.replace("<h1>", "<!-- TODO: remove admin password before launch --><h1>"), expect: ["exposure.html-comments"] },
  { name: "tham chiếu địa chỉ nội bộ", body: GOOD_BODY.replace("<h1>", '<script>fetch("http://10.0.3.12:8080/api/users")</script><h1>'), expect: ["exposure.internal-references"] },
  { name: "khoá bí mật trong HTML", body: GOOD_BODY.replace("<h1>", `<script>var k="${["sk", "live", "Z9y8X7w6V5u4T3s2R1q0P9o8"].join("_")}";</script><h1>`), expect: ["exposure.secrets"] },
  { name: "script CDN thiếu SRI", body: GOOD_BODY.replace('<script src="/app.js">', '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script><script src="/app.js">'), expect: ["browser.third-party-integrity"] },
  { name: "form mật khẩu gửi sang website khác", body: GOOD_BODY.replace("<h1>", '<form method="post" action="https://thu-ba.example.net/login"><input type="password" name="p"></form><h1>'), expect: ["browser.form-targets"] },
  { name: "header gỡ lỗi", headers: { "x-debug-token": "a1b2c3", "x-runtime": "0.0421" }, expect: ["config.debug-headers"] },
  { name: "không có security.txt", securityTxt: false, expect: ["exposure.security-txt"] },
  // ---- bẫy báo nhầm: các site này KHÔNG được bị báo lỗi sai
  { name: "SPA trả 200 + HTML cho mọi đường dẫn (không có security.txt thật)", spa: true, expect: ["exposure.security-txt"] },
  { name: "script CDN có SRI đầy đủ", body: GOOD_BODY.replace('<script src="/app.js">', '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" integrity="sha384-AAAA" crossorigin="anonymous"></script><script src="/app.js">'), expect: [] },
  { name: "form đăng nhập POST cùng origin", body: GOOD_BODY.replace("<h1>", '<form method="post" action="/login"><input type="password" name="p" autocomplete="current-password"></form><h1>'), expect: [] },
  { name: "ghi chú HTML vô hại + điều kiện IE", body: GOOD_BODY.replace("<h1>", "<!-- header start --><!--[if IE]><p>cũ</p><![endif]--><h1>"), expect: [] },
  { name: "ảnh cùng origin + liên kết http:// ra ngoài (không phải tài nguyên)", body: GOOD_BODY.replace("<h1>", '<img src="/a.png"><a href="http://example.org/">liên kết</a><h1>'), expect: [] },
  { name: "không có DMARC", dmarc: null, expect: ["config.dns-email-security"] },
];

// ---------------------------------------------------------------- bộ tải giả lập có đáp án
function dohAnswer(url: URL, s: Site): Response {
  const name = url.searchParams.get("name")!, type = Number(url.searchParams.get("type") ?? 1);
  const A = (data: string, t: number) => ({ type: t, data });
  const table: Record<string, ReturnType<typeof A>[]> = {
    [`${HOST}|16`]: [A('"v=spf1 -all"', 16)],
    [`_dmarc.${HOST}|16`]: s.dmarc === null ? [] : [A(`"${s.dmarc ?? "v=DMARC1; p=reject; rua=mailto:dmarc@bench-site.com"}"`, 16)],
    [`${HOST}|257`]: [A('0 issue "letsencrypt.org"', 257)],
    [`${HOST}|2`]: [A("ns1.bench-dns.net.", 2), A("ns2.bench-dns.org.", 2)],
    [`${HOST}|1`]: [A("93.184.216.34", 1)],
  };
  return new Response(JSON.stringify({ Status: 0, AD: url.searchParams.get("do") === "1", Answer: table[`${name}|${type}`] ?? [] }));
}

function siteFetch(s: Site): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.hostname === "cloudflare-dns.com") return dohAnswer(url, s);
    const headersOf = () => {
      const h = new Headers();
      const merged = { ...GOOD_HEADERS, ...(s.headers ?? {}) };
      for (const [k, v] of Object.entries(merged)) if (v !== null) h.set(k, v);
      for (const c of s.cookies ?? []) h.append("set-cookie", c);
      return h;
    };
    if (url.hostname === `www.${HOST}`) return new Response(null, { status: 301, headers: { location: `https://${HOST}/` } });
    if (url.hostname !== HOST) return new Response("", { status: 404 });
    if (url.protocol === "http:") return s.httpNoRedirect ? new Response(s.body ?? GOOD_BODY, { headers: headersOf() }) : new Response(null, { status: 301, headers: { location: `https://${HOST}${url.pathname}` } });
    const spaFallback = s.spa && url.pathname !== "/";
    switch (spaFallback ? "*spa*" : url.pathname) {
      case "*spa*": return new Response(GOOD_BODY, { status: 200, headers: headersOf() });
      case "/": {
        const h = headersOf();
        const origin = (init?.headers as Record<string, string> | undefined)?.origin;
        if (s.corsReflect && origin) { h.set("access-control-allow-origin", origin); h.set("access-control-allow-credentials", "true"); }
        return new Response(s.body ?? GOOD_BODY, { headers: h });
      }
      case "/robots.txt": return new Response("User-agent: *\nAllow: /\n", { headers: { "content-type": "text/plain" } });
      case "/sitemap.xml": return new Response('<?xml version="1.0"?><urlset></urlset>', { headers: { "content-type": "application/xml" } });
      case "/.well-known/security.txt": return s.securityTxt === false ? new Response("not found", { status: 404 }) : new Response(SECURITY_TXT, { headers: { "content-type": "text/plain" } });
      default: { const h = headersOf(); return new Response(s.notFound ?? "<html><h1>404</h1></html>", { status: 404, headers: h }); } // site chuẩn gửi header cả ở trang lỗi
    }
  }) as typeof fetch;
}

const resolver: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];

describe("tập đối chiếu: bộ quét thật trên website có đáp án biết trước", () => {
  const stats = new Map<string, { tp: number; fp: number; fn: number }>();
  const bump = (id: string, k: "tp" | "fp" | "fn") => { const s = stats.get(id) ?? { tp: 0, fp: 0, fn: 0 }; s[k]++; stats.set(id, s); };

  it.each(SITES)("$name", async (site) => {
    const out = await runQuickScan(HOST, { resolver, fetchImpl: siteFetch(site) });
    const flagged = new Set(out.items.filter((i) => i.status !== "pass").map((i) => i.tech!.ruleId));
    const want = new Set(site.expect);
    for (const id of want) bump(id, flagged.has(id) ? "tp" : "fn");
    for (const id of flagged) if (!want.has(id)) bump(id, "fp");
    const missed = [...want].filter((x) => !flagged.has(x));
    const extra = [...flagged].filter((x) => !want.has(x));
    expect({ site: site.name, missed, extra }).toEqual({ site: site.name, missed: [], extra: [] });
  });

  it("tổng kết: độ chính xác / độ phủ theo luật", () => {
    const rows = [...stats].map(([rule, s]) => ({ rule, TP: s.tp, FP: s.fp, FN: s.fn, precision: s.tp + s.fp ? +(s.tp / (s.tp + s.fp)).toFixed(2) : 1, recall: s.tp + s.fn ? +(s.tp / (s.tp + s.fn)).toFixed(2) : 1 }));
    // eslint-disable-next-line no-console
    console.table(rows);
    expect(rows.reduce((a, r) => a + r.FP + r.FN, 0)).toBe(0);
  });
});
