import { describe, expect, it } from "vitest";
import { explain } from "../explain";
import { ALL_RULES } from "../rules";
import { baseline, hdr, rec, run } from "./fixtures";
import type { Finding, FindingStatus } from "../types";

/** Biến thể (khoá fingerprint) mà từng luật thật sự phát ra; "" = không có khoá riêng. */
const VARIANTS: Record<string, string[]> = {
  "headers.broken": ["xfo", "xcto", "hsts-no-maxage", "hsts-zero", "csp-unquoted", "csp-meta-ignored", "referrer", "permissions", "xss-protection"], "headers.deprecated": ["pragma"],
  "headers.csp": ["", "x"], "browser.cors": [""], "cookies.flags": ["sid"], "config.dns-email-security": ["na-platform", "dmarc", "dmarc-policy", "dmarc-pct", "spf", "spf-plus-all", "spf-neutral", "spf-lookups", "spf-multiple", "caa", "dnssec", "mta-sts", "ns-single"],
  "tls.certificate-strength": ["weak-key", "long-validity", "wildcard"], "tls.hsts-preload": ["invalid", "missing"], "tls.cipher-suite": ["weak", "legacy"],
  "tls.insecure-login-form": ["action:x.com/login", "method-get", "page-http"], "config.suspicious-redirects": ["downgrade:a", "long:a", "ip:a", "blocked:a", "meta-refresh", "cross-domain"],
  "headers.cache-policy": ["missing", "cookie-cacheable"], "config.http-methods": ["trace", "write-methods"], "exposure.public-config": ["sensitive-names", "list"],
  "adv.shared-cache-leak": ["hit", "public"],
};
const CERT = new Set(["confirmed", "potential", "inconclusive"]);
const mk = (ruleId: string, key: string, status: FindingStatus, summary: string, confidence: Finding["confidence"] = "medium"): Finding => ({
  ruleId, title: "t", category: "Headers", severity: status === "fail" ? "medium" : "info", confidence, status, summary, explanation: "e", evidence: ["x-header: giá trị"], remediation: null, affectedUrl: null, references: [], fingerprint: `${ruleId}|${key}`,
});

describe("chất lượng giải thích — phủ toàn bộ luật", () => {
  it("có đúng 63 luật và MỌI luật có mẫu giải thích riêng (không còn fallback)", () => {
    expect(ALL_RULES).toHaveLength(63);
    const bare: string[] = [];
    for (const r of ALL_RULES) {
      for (const key of VARIANTS[r.id] ?? [""]) {
        const e = explain(mk(r.id, key, "fail", "Một mô tả cụ thể của phát hiện này."), "example.com");
        if (!e.specific) bare.push(`${r.id}|${key}`);
      }
    }
    expect(bare, `còn dùng fallback: ${bare.join(", ")}`).toEqual([]);
  });

  it.each(ALL_RULES.flatMap((r) => (VARIANTS[r.id] ?? [""]).map((k) => [r.id, k] as const)))("%s [%s]: đủ bằng chứng → nguyên nhân → hệ quả → cách sửa → cách xác minh", (id, key) => {
    const e = explain(mk(id, key, "fail", "Một mô tả cụ thể của phát hiện này."), "example.com");
    expect(e.saw.length, "saw").toBeGreaterThan(15);
    expect(e.why.length, "why").toBeGreaterThan(25);
    expect(e.consequence.length, "consequence").toBeGreaterThan(15);
    expect(e.steps.length, "steps").toBeGreaterThan(0);
    for (const s of e.steps) expect(s.text.length).toBeGreaterThan(10);
    expect(e.expect.length, "expect").toBeGreaterThan(10);
    expect(CERT.has(e.certainty)).toBe(true);
    expect(e.caveat.length, "caveat").toBeGreaterThan(20);
    expect(e.verify.length, "verify (lệnh kiểm tra lại)").toBeGreaterThan(5);
    expect(`${e.saw}${e.why}${e.consequence}${e.verify}`).not.toMatch(/undefined|\[object|NaN/);
    expect(e.verify).not.toMatch(/\bHOST\b/);
  });

  it("không khẳng định “đã bị tấn công/khai thác” khi chỉ có bằng chứng cấu hình", () => {
    const overclaim = /(đã bị (tấn công|khai thác|xâm nhập|đánh cắp)|chắc chắn bị|đang bị (tấn công|khai thác)|kẻ tấn công đã)/i;
    for (const r of ALL_RULES) for (const key of VARIANTS[r.id] ?? [""]) {
      const e = explain(mk(r.id, key, "fail", "Một mô tả cụ thể của phát hiện này."), "example.com");
      expect(`${e.saw} ${e.why} ${e.consequence}`, `${r.id}|${key}`).not.toMatch(overclaim);
    }
  });

  it("phân biệt xác nhận được / tiềm năng / chưa kết luận", () => {
    expect(explain(mk("tls.https-available", "", "unknown", "Không kết nối ổn định"), "example.com").certainty).toBe("inconclusive");
    expect(explain(mk("exposure.secrets", "k", "fail", "Chuỗi giống khoá"), "example.com").certainty).toBe("potential");
    expect(explain(mk("adv.dom-xss-flow", "", "fail", "location.hash → innerHTML", "low"), "example.com").certainty).toBe("potential");
    expect(explain(mk("tls.protocol-version", "", "fail", "Máy chủ vẫn chấp nhận TLS 1.0"), "example.com").certainty).toBe("confirmed");
    // luật không có mẫu riêng: dựa vào trạng thái + độ tin cậy
    expect(explain(mk("x.unknown", "", "unknown", "?"), "example.com").certainty).toBe("inconclusive");
    expect(explain(mk("x.unknown", "", "fail", "?", "low"), "example.com").certainty).toBe("potential");
  });
});

describe("biến thể thực tế qua toàn bộ engine", () => {
  const withCookie = (o: ReturnType<typeof baseline>, c: string) => { o.https = rec({ headers: { ...hdr(o), "set-cookie": c }, chain: [{ url: "https://example.com/", status: 200, headers: { ...hdr(o), "set-cookie": c } }] }); o.page = o.https; };
  const failOf = (o: ReturnType<typeof baseline>, ruleId: string) => run(o).find((x) => x.ruleId === ruleId && x.status === "fail");

  it("CSP: Report-Only khác thiếu hoàn toàn", () => {
    const o = baseline(); const csp = hdr(o)["content-security-policy"]!; delete hdr(o)["content-security-policy"]; hdr(o)["content-security-policy-report-only"] = csp;
    const e = explain(failOf(o, "headers.csp")!, "example.com");
    expect(e.saw).toMatch(/Report-Only/); expect(e.why).toMatch(/chưa bảo vệ|vẫn chạy/);
    expect(e.certainty).toBe("confirmed");
  });
  it.each([
    ["unsafe-inline", "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'", /unsafe-inline/],
    ["wildcard", "default-src 'self'; script-src * ; object-src 'none'; base-uri 'self'", /mọi host/],
    ["unsafe-eval", "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'", /unsafe-eval/],
    ["data:", "default-src 'self'; script-src 'self' data:; object-src 'none'; base-uri 'self'", /data:/],
  ] as const)("CSP yếu: %s có lời giải thích đúng biến thể", (_n, policy, re) => {
    const o = baseline(); hdr(o)["content-security-policy"] = policy;
    const e = explain(failOf(o, "headers.csp")!, "example.com");
    expect(e.saw).toMatch(re); expect(e.caveat).toMatch(/không tìm lỗi chèn mã|chưa kết luận/);
  });
  it("CORS: null, wildcard, wildcard+credentials được phân biệt", () => {
    const set = (acao: string, acac: string | null) => { const o = baseline(); o.cors = { testedOrigin: "https://vibesec-cors-probe.invalid", status: 200, acao, acac, vary: null }; return explain(failOf(o, "browser.cors")!, "example.com"); };
    expect(set("null", null).saw).toMatch(/null/);
    expect(set("*", null).certainty).toBe("potential");
    expect(set("*", "true").why).toMatch(/từ chối tổ hợp/);
  });
  it("Cookie: nêu đúng cờ thiếu và tên cookie", () => {
    const o = baseline(); withCookie(o, "session=abc; Path=/; HttpOnly");
    const e = explain(failOf(o, "cookies.flags")!, "example.com");
    expect(e.saw).toMatch(/session/); expect(e.why).toMatch(/Thiếu Secure/); expect(e.why).not.toMatch(/Thiếu HttpOnly/);
  });
  it("SPF/DMARC/NS: mọi biến thể nhận mẫu riêng, không nhầm với biến thể khác", () => {
    const o = baseline(); o.dns = { ...o.dns!, spf: "v=spf1 +all", spfRecords: 1 };
    const e = explain(failOf(o, "config.dns-email-security")!, "example.com");
    expect(e.specific).toBe(true); expect(e.saw).toMatch(/\+all/);
  });
  it("mọi phát hiện không-pass trong một website “tệ” đều có giải thích riêng", () => {
    const o = baseline();
    Object.assign(hdr(o), { server: "nginx/1.18.0", "x-powered-by": "PHP/7.2", "x-debug-token": "abc" });
    delete hdr(o)["strict-transport-security"]; delete hdr(o)["content-security-policy"]; delete hdr(o)["x-frame-options"]; delete hdr(o)["referrer-policy"];
    o.dns = { ...o.dns!, dmarc: null, spf: null, caa: [] };
    const bad = run(o).filter((f) => f.status !== "pass");
    expect(bad.length).toBeGreaterThan(5);
    for (const f of bad) expect(explain(f, "example.com").specific, f.ruleId + "|" + f.fingerprint).toBe(true);
  });
});

describe("false positive: cấu hình hợp lệ nhưng ít phổ biến", () => {
  const nonPass = (o: ReturnType<typeof baseline>, id: string) => run(o).filter((f) => f.ruleId === id && f.status !== "pass");
  it("strict CSP (nonce + strict-dynamic + 'unsafe-inline' + https: dự phòng) không bị báo yếu", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'";
    expect(nonPass(o, "adv.csp-analysis")).toEqual([]); expect(nonPass(o, "headers.csp")).toEqual([]);
  });
  it("'unsafe-inline' chỉ ở style-src không bị tính là script yếu", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
    expect(nonPass(o, "headers.csp")).toEqual([]);
  });
  it("cookie CSRF cho JS đọc không bị coi là cookie phiên thiếu __Host-", () => {
    const o = baseline(); const c = "XSRF-TOKEN=abc; Path=/; Secure; SameSite=Lax";
    o.https = rec({ headers: { ...hdr(o), "set-cookie": c }, chain: [{ url: "https://example.com/", status: 200, headers: { ...hdr(o), "set-cookie": c } }] }); o.page = o.https;
    expect(nonPass(o, "cookies.prefix")).toEqual([]); expect(nonPass(o, "cookies.flags")).toEqual([]);
  });
  it("giá trị header khác kiểu viết vẫn hợp lệ: HSTS viết hoa/nháy kép, X-Frame-Options chữ thường, Referrer-Policy nhiều giá trị", () => {
    for (const [h, v] of [["strict-transport-security", 'max-age="31536000"; includeSubDomains'], ["strict-transport-security", "MAX-AGE=31536000;"], ["x-frame-options", "sameorigin"], ["referrer-policy", "no-referrer, strict-origin-when-cross-origin"]] as const) {
      const o = baseline(); hdr(o)[h] = v;
      expect(run(o).filter((f) => ["tls.hsts", "headers.broken", "headers.frame-protection", "privacy.referrer-policy"].includes(f.ruleId) && f.status !== "pass"), `${h}: ${v}`).toEqual([]);
    }
  });
  it("CORS trả đúng một origin tin cậy (không phản chiếu) là hợp lệ", () => {
    const o = baseline(); o.cors = { testedOrigin: "https://vibesec-cors-probe.invalid", status: 200, acao: "https://app.example.com", acac: "true", vary: "Origin" };
    expect(nonPass(o, "browser.cors")).toEqual([]);
  });
  it("thiếu dữ liệu TLS: không bịa kết luận về chứng chỉ", () => {
    const o = baseline(); o.https!.tls = null as never;
    expect(run(o).filter((f) => f.ruleId.startsWith("tls.certificate") && f.status === "fail")).toEqual([]);
  });
});

describe("audit nội dung: không biến điểm cao hoặc cấu hình thành lời bảo chứng", () => {
  it("lời giải thích điểm không bao giờ nói “an toàn tuyệt đối”, kể cả khi 0 vấn đề", async () => {
    const { plainScore } = await import("@/lib/feynman");
    for (const [score, issues, urgent] of [[100, 0, 0], [95, 0, 0], [85, 3, 0], [65, 6, 0], [30, 12, 2]] as const) {
      const t = plainScore(score, issues, urgent);
      expect(t).not.toMatch(/(?<!không có nghĩa là website )an toàn tuyệt đối|hoàn toàn an toàn|không thể bị hack/i);
    }
    expect(plainScore(100, 0, 0)).toMatch(/không có nghĩa là website an toàn tuyệt đối/);
    expect(plainScore(85, 3, 0)).toMatch(/không phải bảo chứng/);
  });
  it("chatbot trả lời “có chắc không?” bằng mức chắc chắn + giới hạn bằng chứng", async () => {
    const { answerFocused } = await import("@/lib/matmat");
    const f = mk("adv.dom-xss-flow", "", "fail", "location.hash → innerHTML", "low");
    const r = answerFocused("Có chắc là đúng không?", { finding: f, host: "example.com" });
    expect(r.text).toMatch(/rủi ro tiềm năng/); expect(r.text).toMatch(/phân tích tĩnh/);
  });
  it("mọi giải thích ‘tiềm năng’ phải có caveat nêu giới hạn và không dùng từ khẳng định tuyệt đối", () => {
    const absolute = /\b(chắc chắn (bị|sẽ)|luôn luôn bị|100% (an toàn|bị)|không thể (bị )?(hack|tấn công))/i;
    for (const r of ALL_RULES) for (const key of VARIANTS[r.id] ?? [""]) {
      const e = explain(mk(r.id, key, "fail", "Một mô tả cụ thể của phát hiện này."), "example.com");
      expect(`${e.saw} ${e.why} ${e.consequence} ${e.caveat}`, `${r.id}|${key}`).not.toMatch(absolute);
    }
  });
});

describe("tên miền con của nền tảng: DNS/email là KHÔNG ÁP DỤNG (không đạt, không lỗi)", () => {
  it.each(["myapp.vercel.app", "shop.netlify.app", "api.tridinhbui.workers.dev", "me.github.io", "proj.pages.dev"])("%s → một mục ‘tham khảo’, không trừ điểm, không tra DNS của nền tảng", (host) => {
    const o = baseline();
    o.target = { ...o.target, host, url: `https://${host}/`, origin: `https://${host}` };
    o.dns = null; o.platformSuffix = host.split(".").slice(-2).join(".");
    const fs = run(o).filter((f) => f.ruleId === "config.dns-email-security" || f.ruleId.startsWith("adv.spf") || f.ruleId.startsWith("adv.dmarc"));
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({ status: "info", severity: "info" });
    const e = explain(fs[0]!, host);
    expect(e.specific).toBe(true); expect(e.saw).toMatch(new RegExp(o.platformSuffix.replace(".", "\\.")));
    expect(e.consequence).toMatch(/không trừ điểm/);
  });
  it("platformSuffix nhận đúng nền tảng nhưng KHÔNG nhầm tên miền riêng (kể cả .com.vn)", async () => {
    const { platformSuffix, dnsApex } = await import("../platform-domain");
    expect(platformSuffix("security.tridinhbui0901.workers.dev")).toBe("workers.dev");
    expect(platformSuffix("x.vercel.app")).toBe("vercel.app");
    expect(platformSuffix("shop.example.com.vn")).toBeNull();
    expect(platformSuffix("www.example.com")).toBeNull();
    expect(platformSuffix("vercel.app")).toBeNull();
    expect(dnsApex("shop.example.com.vn")).toBe("example.com.vn");
    expect(dnsApex("www.example.com")).toBe("example.com");
  });
  it("lời giải thích DNS nêu đúng tên miền đã tra (tên miền gốc), không phải tên miền con", () => {
    const o = baseline(); o.dns = { ...o.dns!, caa: [] };
    const f = run(o).find((x) => x.ruleId === "config.dns-email-security" && x.status === "fail")!;
    expect(explain(f, "shop.example.com").saw).toMatch(/Tên miền example\.com /);
  });
});
