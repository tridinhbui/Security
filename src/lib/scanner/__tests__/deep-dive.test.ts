import { describe, expect, it } from "vitest";
import { DEEP_DIVE, KIND_LABEL } from "../deep-dive";
import { ALL_RULES } from "../rules";
import { explain } from "../explain";
import { IMPACT } from "../impact";
import { FIXES } from "../fixes";
import { FEYNMAN } from "../../feynman";
import { PLAIN_TITLES } from "../../beginner";
import { OWASP_MAP } from "../../guidance";
import { STANDARDS } from "../../standards";
import { baseline, failing, hdr } from "./fixtures";
import type { Finding } from "../types";

const RULE_IDS = ALL_RULES.map((r) => r.id);

describe("nhất quán nội dung giữa các tầng", () => {
  it.each(RULE_IDS)("%s có đủ: tiêu đề dễ hiểu, hình dung đơn giản, tác động, tiêu chuẩn tham chiếu", (id) => {
    expect(PLAIN_TITLES[id], "beginner.ts PLAIN_TITLES").toBeTruthy();
    expect(FEYNMAN[id], "feynman.ts FEYNMAN").toBeTruthy();
    expect(IMPACT[id], "impact.ts IMPACT").toBeTruthy();
    expect(id in STANDARDS, "standards.ts STANDARDS").toBe(true);
  });

  it("không có khoá mồ côi: mọi khoá nội dung đều trỏ tới luật có thật", () => {
    const known = new Set(RULE_IDS);
    for (const [name, table] of Object.entries({ PLAIN_TITLES, FEYNMAN, IMPACT, STANDARDS, OWASP_MAP, FIXES, DEEP_DIVE })) {
      const orphans = Object.keys(table).filter((k) => !known.has(k));
      expect(orphans, `${name} có khoá không tồn tại`).toEqual([]);
    }
  });

  it("không tuyên bố an toàn tuyệt đối ở bất kỳ nội dung nào", () => {
    const banned = /(an toàn tuyệt đối|hoàn toàn an toàn|100% an toàn|không thể bị (tấn công|hack|xâm nhập)|bất khả xâm phạm|đã được bảo vệ hoàn toàn)/i;
    const blobs: [string, string][] = [];
    for (const [id, f] of Object.entries(FEYNMAN)) blobs.push([`feynman:${id}`, `${f.like} ${f.todo}`]);
    for (const [id, i] of Object.entries(IMPACT)) blobs.push([`impact:${id}`, `${i.today} ${i.worst} ${i.who}`]);
    for (const [id, d] of Object.entries(DEEP_DIVE)) blobs.push([`deep:${id}`, [d.mechanism, ...d.mistakes, ...d.tradeoffs].join(" ")]);
    for (const [where, text] of blobs) expect(text, where).not.toMatch(banned);
  });
});

describe("tầng “Đào sâu kỹ thuật”", () => {
  const entries = Object.entries(DEEP_DIVE);

  it("phủ các lỗi phổ biến và nguy hiểm nhất", () => {
    for (const id of ["headers.csp", "tls.hsts", "cookies.flags", "browser.cors", "exposure.secrets", "exposure.public-config", "config.dns-email-security", "tls.http-to-https-redirect", "exposure.subdomain-takeover", "adv.web-storage-secrets"]) {
      expect(DEEP_DIVE[id], id).toBeDefined();
    }
  });

  it.each(entries)("%s: cấu trúc đầy đủ, nguồn chính thống, lệnh kiểm tra chỉ đọc", (_id, d) => {
    expect(KIND_LABEL[d.kind]).toBeDefined();
    expect(d.mechanism.length).toBeGreaterThan(80);
    expect(d.frameworks.length).toBeGreaterThan(0);
    expect(d.mistakes.length).toBeGreaterThanOrEqual(2);
    expect(d.tradeoffs.length).toBeGreaterThanOrEqual(1);
    expect(d.verify.length).toBeGreaterThanOrEqual(1);
    expect(d.sources.length).toBeGreaterThanOrEqual(2);
    for (const s of d.sources) expect(s.url).toMatch(/^https:\/\/[a-z0-9.-]+\//i);
    for (const s of d.frameworks) { expect(s.code.trim().length).toBeGreaterThan(5); expect(s.label.length).toBeGreaterThan(2); }
    // lệnh kiểm tra không được thay đổi gì trên hệ thống
    for (const v of d.verify) expect(v, "verify phải chỉ đọc").not.toMatch(/(-X\s*(POST|PUT|DELETE|PATCH)\b|\brm\s|--data|-d\s|\bsudo\b|certbot (renew|certonly))/);
    // ví dụ trước/sau phải khác nhau
    if (d.exchange) expect(d.exchange.before).not.toEqual(d.exchange.after);
    // không dùng tên đã lỗi thời cho cách sửa Next.js
    for (const s of d.frameworks.filter((x) => x.platform === "nextjs")) expect(s.code).not.toMatch(/export (async )?function middleware/);
    expect(JSON.stringify(d)).not.toMatch(/undefined|\[object|NaN/);
  });

  // Mẫu cấu hình phải sạch: áp lên website mẫu đã cứng hoá, các luật liên quan không được báo lỗi.
  const withExamples = entries.filter(([, d]) => d.examples?.length);
  it("có ví dụ header được kiểm chứng", () => expect(withExamples.length).toBeGreaterThanOrEqual(6));
  it.each(withExamples.flatMap(([id, d]) => d.examples!.map((e) => [id, e.name, e.value, e.checks ?? d.checks ?? [id], e.allow ?? []] as const)))("%s: mẫu %s không tạo phát hiện lỗi mới", (_id, name, value, checks, allow) => {
    const o = baseline();
    const h = hdr(o);
    // Mẫu thay thế hẳn header gốc: gỡ các header cùng họ để chứng minh chính mẫu này đủ.
    if (name === "x-frame-options" || name === "content-security-policy") { delete h["x-frame-options"]; }
    h[name] = value;
    const bad: Finding[] = checks.flatMap((c) => failing(o, c));
    expect(bad.map((f) => `${f.ruleId}|${f.fingerprint}: ${f.summary}`)).toEqual([]);
    // và không làm xuất hiện lỗi ở BẤT KỲ luật nào khác so với website mẫu
    const keep = (f: Finding) => !allow.includes(f.ruleId);
    expect(failing(o).filter(keep).map((f) => f.fingerprint)).toEqual(failing(baseline()).filter(keep).map((f) => f.fingerprint));
  });
});

describe("hồi quy các sai sót nội dung đã sửa trong đợt audit", () => {
  const mk = (ruleId: string): Finding => ({ ruleId, title: "t", category: "Privacy", severity: "low", confidence: "medium", status: "fail", summary: "Không có header Referrer-Policy nào được gửi.", explanation: "e", evidence: ["referrer-policy: (không có)"], remediation: null, affectedUrl: null, references: [], fingerprint: `${ruleId}|` });

  it("Referrer-Policy: không nói trình duyệt hiện đại gửi URL đầy đủ khi không đặt chính sách", () => {
    const e = explain(mk("privacy.referrer-policy"), "example.com");
    expect(e.why).toMatch(/strict-origin-when-cross-origin/);
    expect(`${e.why} ${e.consequence}`).toMatch(/trình duyệt (cũ|đời cũ)/);
    expect(IMPACT["privacy.referrer-policy"]!.today).toMatch(/hiện đại/);
  });

  it("Thời hạn chứng chỉ: nêu giới hạn 200 ngày từ 15/3/2026, không còn chỉ nói 398 ngày", () => {
    const f = { ...mk("tls.certificate-strength"), fingerprint: "tls.certificate-strength|long-validity", summary: "Chứng chỉ có thời hạn 500 ngày" };
    const e = explain(f, "example.com");
    expect(e.why).toMatch(/200 ngày/);
    expect(e.expect).toMatch(/200 ngày/);
  });

  it("CSP nonce của Next.js dùng proxy.ts (Next 16), không còn chỉ middleware.ts", () => {
    const csp = DEEP_DIVE["headers.csp"]!.frameworks.find((s) => s.platform === "nextjs" && /proxy\.ts/.test(s.label));
    expect(csp?.code).toMatch(/export function proxy\(/);
  });
});
