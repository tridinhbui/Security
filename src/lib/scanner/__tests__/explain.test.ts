import { describe, expect, it } from "vitest";
import { explain } from "../explain";
import { ANALYST } from "../analyst";
import { baseline, hdr, rec, run } from "./fixtures";
import type { Observations } from "../types";

type Mut = { name: string; ruleId: string; apply: (o: Observations) => void; mustMention: RegExp };
const withCookie = (o: Observations, c: string) => { o.https = rec({ headers: { ...hdr(o), "set-cookie": c }, chain: [{ url: "https://example.com/", status: 200, headers: { ...hdr(o), "set-cookie": c } }] }); o.page = o.https; };

const MUTS: Mut[] = [
  { name: "XFO ALLOW-FROM", ruleId: "headers.broken", apply: (o) => { hdr(o)["x-frame-options"] = "ALLOW-FROM https://a.com"; }, mustMention: /ALLOW-FROM/ },
  { name: "nosniff sai", ruleId: "headers.broken", apply: (o) => { hdr(o)["x-content-type-options"] = "yes"; }, mustMention: /yes/ },
  { name: "HSTS thiếu max-age", ruleId: "headers.broken", apply: (o) => { hdr(o)["strict-transport-security"] = "includeSubDomains"; }, mustMention: /max-age/ },
  { name: "HSTS max-age=0", ruleId: "headers.broken", apply: (o) => { hdr(o)["strict-transport-security"] = "max-age=0"; }, mustMention: /max-age=0/ },
  { name: "CSP thiếu dấu nháy", ruleId: "headers.broken", apply: (o) => { hdr(o)["content-security-policy"] = "default-src self; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"; }, mustMention: /self/ },
  { name: "Referrer sai", ruleId: "headers.broken", apply: (o) => { hdr(o)["referrer-policy"] = "banana"; }, mustMention: /banana/ },
  { name: "Permissions sai", ruleId: "headers.broken", apply: (o) => { hdr(o)["permissions-policy"] = "camera 'none'"; }, mustMention: /camera 'none'/ },
  { name: "thiếu HSTS", ruleId: "tls.hsts", apply: (o) => { delete hdr(o)["strict-transport-security"]; }, mustMention: /Strict-Transport-Security/ },
  { name: "thiếu CSP", ruleId: "headers.csp", apply: (o) => { delete hdr(o)["content-security-policy"]; }, mustMention: /Content-Security-Policy/ },
  { name: "CSP yếu", ruleId: "headers.csp", apply: (o) => { hdr(o)["content-security-policy"] = "default-src *; script-src * 'unsafe-inline'"; }, mustMention: /unsafe-inline|mọi host|CSP/ },
  { name: "CORS phản chiếu", ruleId: "browser.cors", apply: (o) => { o.cors = { testedOrigin: "https://vibesec-cors-probe.invalid", status: 200, acao: "https://vibesec-cors-probe.invalid", acac: "true", vary: null }; }, mustMention: /vibesec-cors-probe\.invalid/ },
  { name: "HTTP không chuyển hướng", ruleId: "tls.http-to-https-redirect", apply: (o) => { o.http!.chain = [{ url: "http://example.com/", status: 200, headers: {} }]; o.http!.finalUrl = "http://example.com/"; }, mustMention: /example\.com/ },
  { name: "thiếu security.txt", ruleId: "exposure.security-txt", apply: (o) => { o.files.securityTxt = { url: "https://example.com/.well-known/security.txt", present: false, status: 404, contentType: "", body: "" }; }, mustMention: /security\.txt/ },
  { name: "lộ phiên server", ruleId: "config.server-disclosure", apply: (o) => { hdr(o).server = "nginx/1.18.0"; }, mustMention: /nginx\/1\.18\.0/ },
  { name: "thiếu X-Frame-Options", ruleId: "headers.frame-protection", apply: (o) => { delete hdr(o)["x-frame-options"]; hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"; }, mustMention: /X-Frame-Options/ },
  { name: "thiếu nosniff", ruleId: "headers.x-content-type-options", apply: (o) => { delete hdr(o)["x-content-type-options"]; }, mustMention: /nosniff/ },
  { name: "thiếu Referrer-Policy", ruleId: "privacy.referrer-policy", apply: (o) => { delete hdr(o)["referrer-policy"]; }, mustMention: /Referrer-Policy/ },
  { name: "cookie thiếu cờ", ruleId: "cookies.flags", apply: (o) => withCookie(o, "session=abc; Path=/"), mustMention: /./ },
  { name: "thiếu DMARC", ruleId: "config.dns-email-security", apply: (o) => { o.dns = { ...o.dns!, dmarc: null }; }, mustMention: /DMARC/ },
  { name: "thiếu SPF", ruleId: "config.dns-email-security", apply: (o) => { o.dns = { ...o.dns!, spf: null }; }, mustMention: /SPF/ },
];

describe("giải thích theo từng trường hợp cụ thể", () => {
  it.each(MUTS)("$name", (m) => {
    const o = baseline(); m.apply(o);
    const f = run(o).find((x) => x.ruleId === m.ruleId && x.status === "fail");
    expect(f, `${m.name}: luật không báo lỗi`).toBeTruthy();
    const e = explain(f!, "example.com");
    expect(e.specific, "phải dùng mẫu riêng, không phải câu chung").toBe(true);
    expect(e.saw, "phần “thấy gì” phải nêu chi tiết cụ thể").toMatch(m.mustMention);
    expect(e.saw).not.toBe(ANALYST[m.ruleId]?.statement);
    expect(e.why.length).toBeGreaterThan(40);
    expect(e.consequence.length).toBeGreaterThan(20);
    expect(e.steps.length).toBeGreaterThan(0);
    expect(e.steps.every((s) => s.text.length > 10)).toBe(true);
    expect(e.expect.length).toBeGreaterThan(10);
    expect(e.notes).toHaveLength(f!.evidence.length);
    for (const n of e.notes) expect(n.note.length).toBeGreaterThan(5);
  });

  it("mọi phát hiện lỗi (kể cả luật chưa có mẫu riêng) vẫn có giải thích dựng từ dữ liệu thật, không rỗng", () => {
    const o = baseline();
    Object.assign(hdr(o), { "x-debug-token": "abc", server: "Apache/2.4.41", "x-powered-by": "PHP/7.2" });
    delete hdr(o)["content-security-policy"];
    const fails = run(o).filter((f) => f.status === "fail");
    expect(fails.length).toBeGreaterThan(2);
    for (const f of fails) {
      const e = explain(f, "example.com");
      expect(e.saw.length, f.ruleId).toBeGreaterThan(15);
      expect(e.why.length, f.ruleId).toBeGreaterThan(15);
      expect(e.steps.length, f.ruleId).toBeGreaterThan(0);
    }
  });
});

import { answerFocused, reply } from "@/lib/matmat";
describe("chatbot trả lời theo mục đang hỏi (không AI)", () => {
  const o = baseline(); hdr(o)["x-frame-options"] = "ALLOW-FROM https://a.com";
  const f = run(o).find((x) => x.ruleId === "headers.broken" && x.status === "fail")!;
  const focus = { finding: f, host: "example.com", line: "x-frame-options: ALLOW-FROM https://a.com" };

  it("hỏi về dòng bằng chứng: giải thích đúng dòng đó và vì sao nó chứng minh vấn đề", () => {
    const r = answerFocused("Dòng này nghĩa là gì?", focus);
    expect(r.text).toContain("ALLOW-FROM");
    expect(r.text).toMatch(/không nằm trong danh sách|bỏ qua/);
  });
  it("hỏi vì sao / nguy hiểm / làm gì / có đúng không đều ra nội dung riêng của mục", () => {
    expect(answerFocused("Vì sao đây là vấn đề?", focus).text).toMatch(/DENY hoặc SAMEORIGIN/);
    expect(answerFocused("Có nghiêm trọng không?", focus).text).toMatch(/Trong 1 ngày|Mức độ/);
    const fix = answerFocused("Mình phải làm gì để sửa?", focus);
    expect(fix.text).toMatch(/DENY/); expect(fix.copy).toBeTruthy();
    expect(answerFocused("Có chắc là đúng không, có báo nhầm không?", focus).text).toMatch(/curl -sI/);
  });
  it("câu hỏi dài, tự do vẫn được trả lời theo mục đang chọn (không cần giải thích lại ngữ cảnh)", () => {
    const long = "Mình chạy quét trên website của công ty mình, kết quả có một lỗi mà mình không hiểu, mình không phải dân kỹ thuật nên muốn biết cụ thể nó đang nói gì và mình có cần nhờ ai không. " .repeat(3);
    const r = reply(long, null, focus);
    expect(r.text).toContain("ALLOW-FROM");
  });
  it("xin gặp người thật vẫn chuyển sang đội hỗ trợ dù đang có mục được chọn", () => {
    expect(reply("cho mình gặp người thật", null, focus).handoff).toBe(true);
  });
});
