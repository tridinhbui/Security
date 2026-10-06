import { describe, expect, it } from "vitest";
import { OWASP_MAP } from "../guidance";
import { ALL_RULES } from "../scanner/rules";
import { OWASP_TOP10, owaspCoverage, STANDARDS, standardsFor } from "../standards";
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
    const a02 = rows.find((r) => r.code === "A02")!;
    expect(a02.failing).toBe(1);
    expect(a02.passing).toBe(1);
    expect(rows.find((r) => r.code === "A09")!.checks).toBe(0);
    expect(rows).toHaveLength(10);
  });
  it("hạng mục không thể quét thụ động được ghi rõ", () => {
    expect(OWASP_TOP10.filter((t) => t.reach === "none").map((t) => t.code)).toEqual(["A09", "A10"]);
  });
});
