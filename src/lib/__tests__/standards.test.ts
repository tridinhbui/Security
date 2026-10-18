import { describe, expect, it } from "vitest";
import { OWASP_MAP } from "../guidance";
import { ALL_RULES } from "../scanner/rules";
import { OWASP_TOP10, owaspCoverage, owaspUrl, STANDARDS, standardsFor } from "../standards";
import type { Finding } from "../scanner/types";

const f = (ruleId: string, status: Finding["status"], severity: Finding["severity"] = "medium"): Finding => ({
  ruleId, title: "t", category: "Headers", severity, confidence: "high", status, summary: "s", explanation: "e", evidence: [], remediation: null, affectedUrl: null, references: [], fingerprint: `${ruleId}|${status}`,
});

describe("chuẩn tham chiếu", () => {
  it("MỌI luật phải có ánh xạ chuẩn (có thể rỗng có chủ đích) và không có ánh xạ mồ côi", () => {
    expect(ALL_RULES.map((r) => r.id).filter((id) => !(id in STANDARDS))).toEqual([]);
    for (const id of Object.keys(STANDARDS)) expect(ALL_RULES.some((r) => r.id === id), `${id} không còn tồn tại`).toBe(true);
  });
  it("định dạng hợp lệ: CWE là số nguyên dương, ASVS dạng x.y.z, WSTG có tiền tố", () => {
    for (const [id, s] of Object.entries(STANDARDS)) {
      for (const c of s.cwe) expect(Number.isInteger(c) && c > 0, id).toBe(true);
      for (const a of s.asvs) expect(a, id).toMatch(/^\d{1,2}\.\d{1,2}\.\d{1,2}$/);
      for (const w of s.wstg) expect(w, id).toMatch(/^WSTG-[A-Z]{4}-\d{2}$/);
    }
  });
  it("luật lạ trả về rỗng thay vì lỗi", () => expect(standardsFor("x.y")).toEqual({ cwe: [], asvs: [], wstg: [] }));
  it("mọi mã OWASP trong OWASP_MAP đều thuộc Top 10", () => {
    const codes = new Set(OWASP_TOP10.map((t) => t.code));
    for (const [rule, list] of Object.entries(OWASP_MAP)) for (const o of list) expect(codes.has(o.slice(0, 3)), `${rule}: ${o}`).toBe(true);
  });
});

describe("độ phủ OWASP Top 10", () => {
  it("đếm theo luật, một luật lỗi thì tính lỗi, bỏ qua ghi chú", () => {
    const rows = owaspCoverage([f("tls.hsts", "fail"), f("tls.hsts", "pass"), f("tls.cipher-suite", "pass"), f("config.technology", "info")], OWASP_MAP);
    const a04 = rows.find((r) => r.code === "A04")!; // 2025: mật mã học là A04
    expect(a04.failing).toBe(1);
    expect(a04.passing).toBe(1);
    expect(rows.find((r) => r.code === "A09")!.checks).toBe(0);
    expect(rows).toHaveLength(10);
  });
  it("hạng mục không thể quét thụ động được ghi rõ", () => {
    expect(OWASP_TOP10.filter((t) => t.reach === "none").map((t) => t.code)).toEqual(["A09"]);
  });
});

describe("OWASP Top 10:2025 (thay cho 2021)", () => {
  const NONE = ["tls.http2", "exposure.robots-txt", "exposure.sitemap-xml", "exposure.security-txt", "config.technology", "config.auth-surface", "adv.endpoint-map", "privacy.trackers", "privacy.third-party-origins"];
  it("mọi luật có ánh xạ 2025, trừ đúng danh sách luật không thuộc rủi ro nào trong Top 10", () => {
    const missing = ALL_RULES.map((r) => r.id).filter((id) => !OWASP_MAP[id]);
    expect(missing.sort()).toEqual([...NONE].sort());
  });
  it("không còn nhãn 2021; mỗi nhãn trỏ tới một hạng mục 2025 có thật", () => {
    for (const labels of Object.values(OWASP_MAP)) for (const l of labels) {
      expect(l).toMatch(/^A(0[1-9]|10):2025 – /);
      expect(OWASP_TOP10.some((t) => l.startsWith(t.code))).toBe(true);
    }
  });
  it("sửa các ánh xạ sai đã kiểm chứng (CWE theo danh sách chính thức)", () => {
    expect(OWASP_MAP["adv.web-storage-secrets"]![0]).toMatch(/^A01/); // CWE-922 thuộc A01
    expect(OWASP_MAP["exposure.secrets"]![0]).toMatch(/^A07/);        // CWE-798 thuộc A07
    expect(OWASP_MAP["config.suspicious-redirects"]![0]).toMatch(/^A04/); // hạ cấp HTTPS, không phải open redirect
    expect(OWASP_MAP["exposure.outdated-libraries"]![0]).toMatch(/^A03/);
    expect(owaspUrl("A03:2025 – x")).toBe("https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/");
  });
});
