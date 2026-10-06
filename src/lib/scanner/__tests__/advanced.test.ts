import { describe, expect, it } from "vitest";
import { BASIC_RULES, ALL_RULES } from "../rules";
import type { Observations, ScriptRef } from "../types";
import { baseline, failing, hdr, run } from "./fixtures";

const f = (o: Observations, id: string) => failing(o, id);
const withJs = (o: Observations, content: string, url = "https://example.com/app.js"): Observations => {
  const s: ScriptRef = { url, inline: false, sameOrigin: true, content };
  o.scripts = [s];
  return o;
};

describe("luật nâng cao", () => {
  it("quét cơ bản không chạy luật nâng cao; quét đầy đủ chạy tất cả", () => {
    expect(BASIC_RULES.some((r) => r.advanced)).toBe(false);
    expect(ALL_RULES.filter((r) => r.advanced).length).toBeGreaterThanOrEqual(15);
    expect(BASIC_RULES.length).toBeLessThan(ALL_RULES.length);
  });

  it("CSP lỏng (unsafe-inline, wildcard, thiếu object-src/base-uri) bị phát hiện, CSP chặt thì đạt", () => {
    const o = baseline();
    expect(f(o, "adv.csp-analysis")).toEqual([]);
    hdr(o)["content-security-policy"] = "default-src *; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com";
    const [x] = f(o, "adv.csp-analysis");
    expect(x!.severity).toBe("medium");
    expect(x!.evidence.join("\n")).toMatch(/unsafe-inline/);
    expect(x!.evidence.join("\n")).toMatch(/object-src/);
  });

  it("nonce + strict-dynamic không bị coi là unsafe-inline", () => {
    const o = baseline();
    hdr(o)["content-security-policy"] = "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
    expect(f(o, "adv.csp-analysis")).toEqual([]);
  });

  it("cookie + cache public/HIT: phát hiện rò rỉ phiên qua cache dùng chung", () => {
    const o = baseline();
    hdr(o)["set-cookie"] = "session=abc; Path=/; Secure; HttpOnly";
    hdr(o)["cache-control"] = "public, max-age=300";
    expect(f(o, "adv.shared-cache-leak")[0]!.severity).toBe("medium");
    hdr(o)["age"] = "120";
    expect(f(o, "adv.shared-cache-leak")[0]!.severity).toBe("high");
    hdr(o)["cache-control"] = "private, no-store";
    expect(f(o, "adv.shared-cache-leak")).toEqual([]);
  });

  it("cookie phiên có Domain và sống 1 năm bị cảnh báo", () => {
    const o = baseline();
    o.https!.chain = [{ url: o.https!.finalUrl, status: 200, headers: { "set-cookie": ["session=abc; Domain=example.com; Max-Age=31536000; Secure; HttpOnly; SameSite=Lax"] } }];
    const [x] = f(o, "adv.cookie-scope");
    expect(x!.evidence.join("\n")).toMatch(/Domain=example\.com/);
    expect(x!.evidence.join("\n")).toMatch(/365 ngày/);
  });

  it("script từ nguồn từng bị chiếm dụng là mức nghiêm trọng; script @latest là trung bình", () => {
    const o = baseline();
    o.scripts = [{ url: "https://cdn.polyfill.io/v3/polyfill.min.js", inline: false, sameOrigin: false }];
    expect(f(o, "adv.supply-chain")[0]!.severity).toBe("critical");
    o.scripts = [{ url: "https://unpkg.com/some-lib/dist/a.js", inline: false, sameOrigin: false }];
    expect(f(o, "adv.supply-chain")[0]!.severity).toBe("medium");
    o.scripts = [{ url: "https://unpkg.com/some-lib@1.2.3/dist/a.js", inline: false, sameOrigin: false }];
    expect(f(o, "adv.supply-chain")).toEqual([]);
  });

  it("DOM XSS: location.hash gần innerHTML bị phát hiện; mã sạch thì đạt", () => {
    const o = withJs(baseline(), "var x=1; el.innerHTML = location.hash.slice(1);");
    expect(f(o, "adv.dom-xss-flow")[0]!.confidence).toBe("low");
    withJs(o, "el.textContent = location.hash.slice(1);");
    expect(f(o, "adv.dom-xss-flow")).toEqual([]);
  });

  it("postMessage thiếu kiểm tra origin và gửi tới '*'", () => {
    const o = withJs(baseline(), "window.addEventListener('message', function(e){ doIt(e.data); }); parent.postMessage(x, '*');");
    expect(f(o, "adv.postmessage")[0]!.evidence).toHaveLength(2);
    withJs(o, "window.addEventListener('message', function(e){ if(e.origin!=='https://a.com')return; doIt(e.data); });");
    expect(f(o, "adv.postmessage")).toEqual([]);
  });

  it("token lưu trong localStorage bị phát hiện", () => {
    const o = withJs(baseline(), "localStorage.setItem('access_token', t); localStorage.setItem('theme','dark');");
    const [x] = f(o, "adv.web-storage-secrets");
    expect(x!.evidence).toHaveLength(1);
    expect(x!.evidence[0]).toContain('setItem("access_token"');
  });

  it("bản đồ endpoint liệt kê API/admin dưới dạng ghi chú (không trừ điểm)", () => {
    const o = withJs(baseline(), "fetch('/api/users'); fetch(\"/admin/panel\"); new WebSocket('wss://live.example.com/ws');");
    const r = run(o, "adv.endpoint-map");
    expect(r[0]!.status).toBe("info");
    expect(r[0]!.evidence.join(" ")).toMatch(/\/api\/users/);
    expect(r[0]!.evidence.join(" ")).toMatch(/\/admin\/panel/);
  });

  it("GraphQL introspection trong mã bị ghi nhận", () => {
    expect(f(withJs(baseline(), "const q = '{ __schema { types { name } } }';"), "adv.graphql-surface")).toHaveLength(1);
  });

  it("chuỗi chuyển hướng: hạ cấp HTTPS→HTTP và quá dài", () => {
    const o = baseline();
    o.http!.chain = [
      { url: "http://example.com/", status: 302, headers: {} }, { url: "https://example.com/", status: 301, headers: {} },
      { url: "http://www.example.com/", status: 301, headers: {} }, { url: "https://a.example.org/", status: 301, headers: {} },
      { url: "https://b.example.net/", status: 200, headers: {} },
    ];
    const [x] = f(o, "adv.redirect-chain");
    expect(x!.severity).toBe("medium");
    expect(x!.evidence.join("\n")).toMatch(/Hạ cấp/);
  });

  it("header chỉ có ở trang chủ, mất ở trang 404", () => {
    const o = baseline();
    o.notFound!.headers = { "content-type": "text/html" };
    const [x] = f(o, "adv.header-consistency");
    expect(x!.evidence[0]).toMatch(/trang lỗi 404 thiếu/);
  });

  it("SPF +all / vượt 10 lần tra; DMARC p=none", () => {
    const o = baseline();
    o.dns!.spf = "v=spf1 +all";
    expect(f(o, "adv.spf-deep")[0]!.severity).toBe("high");
    o.dns!.spf = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(" ") + " -all";
    expect(f(o, "adv.spf-deep")[0]!.evidence.join("\n")).toMatch(/permerror/);
    o.dns!.dmarc = "v=DMARC1; p=none";
    const [d] = f(o, "adv.dmarc-deep");
    expect(d!.severity).toBe("medium");
    expect(d!.evidence.join("\n")).toMatch(/rua/);
  });

  it("chứng chỉ hiệu lực > 398 ngày, tự ký, wildcard", () => {
    const o = baseline();
    Object.assign(o.https!.tls!, { validityDays: 825, selfSigned: true, wildcard: true });
    const [x] = f(o, "adv.certificate-hygiene");
    expect(x!.severity).toBe("medium");
    expect(x!.evidence).toHaveLength(3);
  });

  it("form mật khẩu dùng GET", () => {
    const o = baseline();
    o.html!.forms = [{ action: "https://example.com/login", method: "GET", hasPassword: true }];
    expect(f(o, "adv.form-method")[0]!.severity).toBe("high");
  });
});
