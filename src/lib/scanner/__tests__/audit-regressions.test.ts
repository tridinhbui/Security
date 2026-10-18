import { describe, expect, it } from "vitest";
import { baseline, hdr, rec, run, setHtml } from "./fixtures";
import { calculateScore, effectivePenalties, topRisks } from "../score";
import { coverageGaps, blockedPage } from "../coverage";
import { detectSecrets } from "../secrets";
import { runQuickScan } from "../quick";
import type { Resolver } from "@/lib/ssrf/dns";

/** Hồi quy cho các sai lệch độ chính xác tìm thấy trong đợt audit nội dung & độ tin cậy (xem VIBESEC_CONTENT_USABILITY_SECURITY_AUDIT.md). */
const fails = (o: ReturnType<typeof baseline>, id?: string) => run(o).filter((f) => f.status === "fail" && (!id || f.ruleId === id));

describe("UNKNOWN không thành FAIL, N/A không thành PASS", () => {
  it("A4: security.txt hết thời gian chờ / bị chặn 403 → ‘chưa kiểm tra được’, không phải ‘chưa công bố’", () => {
    for (const probe of [{ status: null, error: "ETIMEDOUT" }, { status: 403 }, { status: 503 }]) {
      const o = baseline();
      o.files.securityTxt = { url: "https://example.com/.well-known/security.txt", present: false, contentType: "", body: "", ...probe } as never;
      const fs = run(o).filter((f) => f.ruleId === "exposure.security-txt");
      expect(fs, JSON.stringify(probe)).toHaveLength(1);
      expect(fs[0]).toMatchObject({ status: "unknown" });
    }
    const o = baseline();
    o.files.securityTxt = { url: "https://example.com/.well-known/security.txt", present: false, status: 404, contentType: "", body: "" };
    expect(fails(o, "exposure.security-txt")).toHaveLength(1); // 404 thật thì vẫn báo
  });
  it("A4: robots/sitemap lỗi mạng → không nói “không có”", () => {
    const o = baseline();
    o.files.robots = { url: "https://example.com/robots.txt", present: false, status: null, contentType: "", body: "", error: "ETIMEDOUT" };
    o.files.sitemap = { url: "https://example.com/sitemap.xml", present: false, status: 429, contentType: "", body: "" };
    expect(run(o).filter((f) => f.ruleId === "exposure.robots-txt" || f.ruleId === "exposure.sitemap-xml")).toEqual([]);
  });
  it("A2/A3: HTTPS không kết nối ổn định, không đọc được TLS, không tra được DNS → báo thiếu phạm vi (pipeline hạ trần điểm)", () => {
    const o = baseline();
    expect(coverageGaps(o)).toEqual([]);
    o.https!.tls = null as never; o.dns = null;
    expect(coverageGaps(o).map((g) => g.code)).toEqual(["tls_unread", "dns_unavailable"]);
    o.https = rec({ status: null, error: { code: "ETIMEDOUT", message: "x" } });
    expect(coverageGaps(o).map((g) => g.code)).toContain("https_unverified");
    o.platformSuffix = "vercel.app";
    expect(coverageGaps(o).map((g) => g.code)).not.toContain("dns_unavailable"); // nền tảng: DNS cố ý không tra, không phải thiếu dữ liệu
  });
  it("A10: trang chủ là trang chặn của tường lửa (403 / “Just a moment…”) được nhận ra", () => {
    const o = baseline();
    expect(blockedPage(o)).toBeNull();
    o.page = rec({ status: 403 });
    expect(blockedPage(o)).toMatchObject({ status: 403 });
    o.page = rec({ status: 200, body: "<html><head><title>Just a moment...</title></head></html>" });
    expect(blockedPage(o)).not.toBeNull();
  });
});

describe("Header lặp / nhiều chính sách (CDN, proxy hai lớp)", () => {
  it("A5: X-Frame-Options ‘SAMEORIGIN, SAMEORIGIN’ và nosniff lặp là hợp lệ", () => {
    const o = baseline(); hdr(o)["x-frame-options"] = "SAMEORIGIN, SAMEORIGIN"; hdr(o)["x-content-type-options"] = "nosniff, nosniff";
    expect(fails(o).filter((f) => ["headers.broken", "headers.frame-protection", "headers.x-content-type-options"].includes(f.ruleId))).toEqual([]);
  });
  it("A5: X-Frame-Options mâu thuẫn ‘DENY, SAMEORIGIN’ vẫn bị báo sai cú pháp (trình duyệt bỏ qua)", () => {
    const o = baseline(); hdr(o)["x-frame-options"] = "DENY, SAMEORIGIN";
    expect(fails(o, "headers.broken")).toHaveLength(1);
  });
  it("A6: hai header CSP (một chặn script, một chỉ có frame-ancestors) → có chống clickjacking, CSP không bị coi là yếu", () => {
    const o = baseline(); delete hdr(o)["x-frame-options"];
    hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self', frame-ancestors 'none'";
    expect(fails(o).filter((f) => ["headers.frame-protection", "headers.csp", "adv.csp-analysis"].includes(f.ruleId))).toEqual([]);
  });
});

describe("Cookie và cache", () => {
  const withCookie = (o: ReturnType<typeof baseline>, c: string, extra: Record<string, string> = {}) => { Object.assign(hdr(o), { "set-cookie": c, ...extra }); };
  it("A7: cookie của CDN (__cf_bm) hoặc ngôn ngữ trên trang được cache → không phải rò rỉ phiên", () => {
    for (const c of ["__cf_bm=x; Path=/; Secure; HttpOnly", "NEXT_LOCALE=vi; Path=/"]) {
      const o = baseline(); withCookie(o, c, { "cf-cache-status": "HIT", age: "42", "cache-control": "public, max-age=300" });
      expect(fails(o).filter((f) => f.ruleId === "adv.shared-cache-leak" || f.fingerprint === "headers.cache-policy|cookie-cacheable"), c).toEqual([]);
    }
  });
  it("A7: cookie phiên thật trên trang được cache vẫn bị báo (mức Trung bình, chưa chứng minh bị phát lại)", () => {
    const o = baseline(); withCookie(o, "session=abc; Path=/; Secure; HttpOnly", { "cf-cache-status": "HIT", "cache-control": "public, max-age=300" });
    expect(fails(o, "adv.shared-cache-leak")[0]).toMatchObject({ severity: "medium" });
  });
  it("A11: cookie bị xoá (Max-Age=0 / Expires quá khứ) khi đăng xuất không bị đánh giá cờ", () => {
    for (const c of ["auth_token=; Path=/; Max-Age=0", "auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]) {
      const o = baseline(); o.https = rec({ headers: { ...hdr(o), "set-cookie": c }, chain: [{ url: "https://example.com/", status: 200, headers: { ...hdr(o), "set-cookie": c } }] }); o.page = o.https;
      expect(fails(o, "cookies.flags"), c).toEqual([]);
    }
  });
  it("A11: cookie phiên đặt trên bước chuyển hướng http:// được nhìn thấy", () => {
    const o = baseline();
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "https://example.com/", chain: [{ url: "http://example.com/", status: 301, headers: { location: "https://example.com/", "set-cookie": "sessionid=abc; Path=/" } }, { url: "https://example.com/", status: 200, headers: hdr(o) }] });
    expect(fails(o, "cookies.flags").map((f) => f.fingerprint)).toContain("cookies.flags|sessionid");
  });
});

describe("Form mật khẩu", () => {
  it("A8: form không ghi method → mức Trung bình, độ tin cậy thấp, chỉ một luật trừ điểm", () => {
    const o = baseline(); setHtml(o, `<!doctype html><html><head><meta charset="utf-8"></head><body><form action="/login"><input type="password" name="p"></form></body></html>`);
    const fs = fails(o).filter((f) => f.ruleId === "tls.insecure-login-form" || f.ruleId === "adv.form-method");
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({ severity: "medium", confidence: "low" });
  });
  it("A8: method=\"get\" ghi rõ vẫn là mức Cao, và chỉ trừ điểm một lần", () => {
    const o = baseline(); setHtml(o, `<!doctype html><html><head><meta charset="utf-8"></head><body><form method="get" action="/login"><input type="password" name="p"></form></body></html>`);
    const fs = run(o);
    expect(fs.filter((f) => f.status === "fail" && f.severity === "high")).toHaveLength(2);
    const eff = effectivePenalties(fs);
    expect(fs.filter((f) => f.status === "fail" && (eff.penalty.get(f.fingerprint) ?? 0) > 0 && /form|login/.test(f.ruleId))).toHaveLength(1);
  });
});

describe("Chấm điểm: một nguyên nhân gốc chỉ trừ một lần", () => {
  it("CSP 'unsafe-inline' (headers.csp + adv.csp-analysis) chỉ trừ 7 điểm và chỉ chiếm một vị trí ‘nên làm trước’", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
    const fs = run(o);
    expect(fs.filter((f) => f.status === "fail").map((f) => f.ruleId).sort()).toEqual(["adv.csp-analysis", "headers.csp"]);
    expect(calculateScore(fs).score).toBe(93);
    expect(topRisks(fs).length).toBe(1);
  });
  it("SPF +all: luật sâu mức Cao không còn kéo trần 79 khi luật cơ bản đã báo cùng nguyên nhân (khoản nặng nhất vẫn được tính)", () => {
    const o = baseline(); o.dns = { ...o.dns!, spf: "v=spf1 +all" };
    const fs = run(o);
    const eff = effectivePenalties(fs);
    const counted = fs.filter((f) => f.status === "fail" && !eff.duplicateOf.has(f.fingerprint));
    expect(counted.filter((f) => /spf/.test(f.fingerprint) || f.ruleId === "adv.spf-deep")).toHaveLength(1);
  });
  it("A9: website không có HTTPS là mức Nghiêm trọng → không thể đạt quá 59", () => {
    const o = baseline(); o.https = rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } });
    const fs = run(o);
    expect(fs.find((f) => f.ruleId === "tls.https-available")).toMatchObject({ severity: "critical" });
    expect(calculateScore(fs).score).toBeLessThanOrEqual(59);
  });
});

describe("Ngữ cảnh tên miền", () => {
  it("đuôi .dev/.app (HSTS preload toàn bộ): HTTP không chuyển hướng & thiếu HSTS là ‘tham khảo’, không trừ điểm", () => {
    const o = baseline();
    o.target = { ...o.target, host: "myapp.dev" };
    delete hdr(o)["strict-transport-security"];
    o.http = rec({ requestedUrl: "http://myapp.dev/", finalUrl: "http://myapp.dev/", chain: [{ url: "http://myapp.dev/", status: 200, headers: {} }] });
    const fs = run(o).filter((f) => ["tls.http-to-https-redirect", "tls.hsts", "tls.hsts-preload"].includes(f.ruleId));
    expect(fs.every((f) => f.status !== "fail")).toBe(true);
    expect(fs.filter((f) => f.status === "info")).toHaveLength(2);
  });
  it("đuôi thường (.com) vẫn báo HTTP không chuyển hướng là lỗi", () => {
    const o = baseline();
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/", chain: [{ url: "http://example.com/", status: 200, headers: {} }] });
    expect(fails(o, "tls.http-to-https-redirect")).toHaveLength(1);
  });
});

describe("Âm tính giả đã sửa", () => {
  it("P1-1: khoá bí mật Supabase kiểu mới sb_secret_ bị phát hiện (critical); sb_publishable_ là công khai theo thiết kế", () => {
    const s = detectSecrets(`const k = "sb_secret_${"N7UND0UgjKTVK"}-Uodkm0Hg_xSvEMPvz";`);
    expect(s[0]).toMatchObject({ id: "supabase-secret-key", severity: "critical" });
    expect(s[0]!.redacted).not.toContain("Uodkm0Hg");
    const pub = detectSecrets(`const k = "sb_publishable_${"abcdefghij"}KLMNOPQRSTuv";`);
    expect(pub[0]).toMatchObject({ id: "supabase-publishable-key", publicByDesign: true });
  });
});

describe("Quét nhanh: không chấm điểm khi dữ liệu không đại diện", () => {
  const resolver: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];
  const HTML = `<!doctype html><html><head><meta charset="utf-8"><title>x</title></head><body>hi</body></html>`;
  const mk = (https: () => Response) => (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) return new Response(JSON.stringify({ Status: 0, Answer: [] }));
    if (url === "http://site.com/") return new Response(HTML, { headers: { "content-type": "text/html" } });
    if (url === "https://site.com/") return https();
    return new Response("nope", { status: 404 });
  }) as typeof fetch;
  it("A1: HTTPS không mở được nhưng HTTP có → từ chối chấm điểm (trước đây ra 90/A)", async () => {
    await expect(runQuickScan("site.com", { resolver, fetchImpl: mk(() => { throw new TypeError("net"); }) })).rejects.toMatchObject({ code: "https_unavailable" });
  });
  it("A10: trang chủ là trang chặn 403 → từ chối chấm điểm, hướng dẫn cho phép bot", async () => {
    await expect(runQuickScan("site.com", { resolver, fetchImpl: mk(() => new Response("<html><title>Access denied</title></html>", { status: 403, headers: { "content-type": "text/html" } })) })).rejects.toMatchObject({ code: "blocked_page" });
  });
});

describe("SPF: hai luật dùng chung một bộ phân tích, không bao giờ kết luận ngược nhau", () => {
  const spfFindings = (spf: string) => { const o = baseline(); o.dns = { ...o.dns!, spf, mx: ["mx.example.com"] }; return run(o).filter((f) => f.ruleId === "adv.spf-deep" || (f.ruleId === "config.dns-email-security" && /spf/i.test(f.fingerprint + f.title))); };
  it.each([
    ["v=spf1 include:_spf.google.com -all", "pass"],
    ["v=spf1 include:_spf.google.com ~all", "pass"],  // softfail: chấp nhận được ở CẢ HAI luật
    ["v=spf1 include:_spf.google.com ?all", "fail"],
    ["v=spf1 include:_spf.google.com", "fail"],        // thiếu all → mặc định trung lập: CẢ HAI luật báo
    ["v=spf1 +all", "fail"],
    ["v=spf1 redirect=_spf.example.net", "pass"],      // kết thúc nằm ở bản ghi khác: không suy đoán
  ])("%s → cả hai luật: %s", (spf, want) => {
    const fs = spfFindings(spf);
    expect(fs.length).toBeGreaterThanOrEqual(2);
    expect(new Set(fs.map((f) => f.status)), spf).toEqual(new Set([want]));
    const sev = new Set(fs.filter((f) => f.status === "fail").map((f) => f.severity));
    expect(sev.size, `mức độ khác nhau giữa hai luật cho ${spf}`).toBeLessThanOrEqual(1);
  });
});

