import { describe, expect, it } from "vitest";
import { IMPACT, urgencyFor } from "../impact";
import { QUICK_RULES, toItems } from "../quick";
import { ALL_RULES } from "../rules";
import { attachFixCommands } from "../fixes";
import { makeFinding } from "../util";

describe("quét nhanh chuyên sâu", () => {
  it("mọi luật trong quét nhanh đều tồn tại và có mô tả hậu quả (“để 1 ngày thì sao”)", () => {
    for (const id of Object.keys(QUICK_RULES)) {
      expect(ALL_RULES.some((r) => r.id === id), `${id} không tồn tại`).toBe(true);
      const i = IMPACT[id];
      expect(i, `${id} thiếu mô tả hậu quả`).toBeTruthy();
      for (const k of ["today", "worst", "who"] as const) expect(i![k].length, `${id}.${k}`).toBeGreaterThan(7);
    }
  });
  it("mức khẩn cấp: Cao/Nghiêm trọng luôn là “ngay hôm nay”; Trung bình → tuần; Thấp → khi rảnh (trừ khi luật ghi đè lên)", () => {
    expect(urgencyFor("tls.hsts", "high")).toBe("now");
    expect(urgencyFor("tls.hsts", "critical")).toBe("now");
    expect(urgencyFor("headers.csp", "medium")).toBe("week");
    expect(urgencyFor("exposure.security-txt", "low")).toBe("later");
    expect(urgencyFor("exposure.secrets", "low")).toBe("now"); // khoá lộ luôn khẩn cấp dù độ tin cậy thấp
  });
  it("mục chưa đạt có hậu quả + giải pháp; mục đạt thì không có (không bịa vấn đề)", () => {
    const base = { category: "Headers" as const, confidence: "high" as const, summary: "s", explanation: "e" };
    const bad = makeFinding({ ruleId: "headers.csp", title: "Thiếu CSP", severity: "medium", status: "fail", ...base, evidence: ["Content-Security-Policy: (không có)"] });
    const ok = makeFinding({ ruleId: "headers.csp", title: "CSP ổn", severity: "info", status: "pass", ...base });
    const [b, g] = toItems(attachFixCommands([bad, ok], { host: "example.com", platforms: [] }));
    const fail = [b!, g!].find((i) => i.status === "fail")!, pass = [b!, g!].find((i) => i.status === "pass")!;
    expect(fail.tech!.impact).toMatchObject({ urgency: "week" });
    expect(fail.tech!.fix.length).toBeGreaterThan(0);
    expect(fail.tech!.fixSummary.length + fail.tech!.fixSteps.length + fail.tech!.fix.length).toBeGreaterThan(0);
    expect(pass.tech!.impact).toBeUndefined();
    expect(pass.tech!.fix).toEqual([]);
  });
});

describe("mô tả hậu quả cho toàn bộ bộ luật (báo cáo đầy đủ)", () => {
  it("mọi luật có thể báo lỗi đều có mô tả hậu quả", () => {
    const INFO_ONLY = new Set(["config.technology", "config.auth-surface"]);
    const missing = ALL_RULES.map((r) => r.id).filter((id) => !INFO_ONLY.has(id) && !IMPACT[id]);
    expect(missing).toEqual([]);
  });
});
