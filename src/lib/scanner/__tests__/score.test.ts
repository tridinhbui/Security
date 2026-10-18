import { describe, expect, it } from "vitest";
import { calculateScore, gradeFor, PASSIVE_SCORE_CEILING, penalty, prioritize, topRisks } from "../score";
import { makeFinding } from "../util";
import type { Finding, Severity, Confidence, FindingStatus } from "../types";
import { AREAS, scanCoverage } from "../scan-coverage";

const f = (severity: Severity, confidence: Confidence = "high", status: FindingStatus = "fail", category: Finding["category"] = "Headers", id = `r.${Math.random()}`) =>
  makeFinding({ ruleId: id, title: `${severity} ${id}`, category, severity, confidence, status, summary: "s", explanation: "e" });

/** Một lượt quét có đủ mọi nhóm kiểm tra (để điểm không bị trần “phạm vi chưa đầy đủ”). */
const full = (): Finding[] => AREAS.map((a) => makeFinding({ ruleId: a.rules[0], title: "ok", category: "Headers", severity: "info", confidence: "high", status: "pass", summary: "s", explanation: "e" }));

describe("scoring", () => {
  it("không bao giờ đạt 100: trần 96 cho quét thụ động, 90 khi phạm vi bị hạn chế", () => {
    const r = calculateScore([...full(), f("info", "high", "info")]);
    expect(r).toMatchObject({ score: 96, ceiling: 96, grade: "A", failed: 0, passed: AREAS.length });
    expect(calculateScore(full(), { limitedCoverage: true })).toMatchObject({ score: 89, ceiling: 89, grade: "B" }); // phạm vi hạn chế: không bao giờ hạng A
    expect(PASSIVE_SCORE_CEILING).toBeLessThan(100);
  });
  it("trần áp dụng cho cả điểm theo nhóm", () => {
    const r = calculateScore([...full(), f("info", "high", "pass", "Headers")]);
    expect(r.categoryScores.Headers).toBe(96);
    expect(calculateScore([f("info", "high", "pass", "Headers")], { limitedCoverage: true }).categoryScores.Headers).toBe(89);
  });
  it("applies severity weights × confidence", () => {
    expect(penalty({ status: "fail", severity: "medium", confidence: "high" })).toBe(7);
    expect(penalty({ status: "fail", severity: "medium", confidence: "low" })).toBeCloseTo(2.8);
    expect(penalty({ status: "pass", severity: "critical", confidence: "high" })).toBe(0);
    expect(penalty({ status: "unknown", severity: "high", confidence: "high" })).toBe(0);
  });
  it("caps: Critical → ≤59, High → ≤79", () => {
    expect(calculateScore([f("critical")]).score).toBe(59);
    expect(calculateScore([f("high")]).score).toBe(79);
    expect(calculateScore([f("critical")]).grade).toBe("F");
    expect(calculateScore([f("high")]).grade).toBe("C");
  });
  it("low-confidence criticals still cap (evidence is what assigns severity)", () => {
    expect(calculateScore([f("critical", "low")]).score).toBeLessThanOrEqual(59);
  });
  it("never goes below 0 and sums many findings", () => {
    const many = Array.from({ length: 20 }, () => f("high"));
    expect(calculateScore(many).score).toBe(0);
  });
  it("grade boundaries", () => {
    expect([100, 90, 89, 80, 79, 70, 69, 60, 59, 0].map(gradeFor)).toEqual(["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]);
  });
  it("category scores are per-category and null when empty", () => {
    const r = calculateScore([...full().map((x) => ({ ...x, category: "Transport Security" as const })), f("medium", "high", "fail", "Headers")]);
    expect(r.categoryScores.Headers).toBe(Math.round(100 - 7 * 1.5));
    expect(r.categoryScores["Transport Security"]).toBe(96);
    expect(r.categoryScores.Privacy).toBeNull();
  });
  it("unknown results do not count towards category coverage", () => {
    expect(calculateScore([f("info", "low", "unknown", "Privacy")]).categoryScores.Privacy).toBeNull();
  });
  it("counts severities for failures only; info notes under info", () => {
    const r = calculateScore([f("high"), f("low"), f("low"), f("high", "high", "pass"), f("info", "high", "info")]);
    expect(r.severityCounts).toEqual({ critical: 0, high: 1, medium: 0, low: 2, info: 1 });
  });
  it("prioritises failures by severity then confidence; passes last", () => {
    const list = [f("info", "high", "pass", "Headers", "z"), f("low", "high", "fail", "Headers", "a"), f("high", "low", "fail", "Headers", "b"), f("high", "high", "fail", "Headers", "c")];
    expect(prioritize(list).map((x) => x.ruleId)).toEqual(["c", "b", "a", "z"]);
    expect(topRisks(list, 2).map((x) => x.ruleId)).toEqual(["c", "b"]);
  });
});

describe("phạm vi quét tách khỏi điểm bảo mật", () => {
  const g = (ruleId: string, status: FindingStatus, key = "") => makeFinding({ ruleId, key: key || undefined, title: "t", category: "Headers", severity: "info", confidence: "high", status, summary: "s", explanation: "e" });
  it("lượt quét thiếu nhóm kiểm tra (vd. không có dữ liệu HTTPS/DNS) không được hạng A dù không có lỗi nào", () => {
    const partial = full().filter((x) => x.ruleId !== "tls.https-available" && x.ruleId !== "config.dns-email-security");
    const r = calculateScore(partial);
    expect(r.coverage).toMatchObject({ complete: false, checked: AREAS.length - 2, applicable: AREAS.length });
    expect(r.grade).not.toBe("A");
    expect(r.score).toBeLessThanOrEqual(89);
  });
  it("UNKNOWN không tính là đã kiểm tra; NOT_APPLICABLE không tính vào mẫu số", () => {
    const fs = full().filter((x) => x.ruleId !== "exposure.security-txt" && x.ruleId !== "config.dns-email-security");
    fs.push(g("exposure.security-txt", "unknown"), g("config.dns-email-security", "info", "na-platform"));
    const c = scanCoverage(fs);
    expect(c.areas.find((a) => a.id === "files")!.state).toBe("unknown");
    expect(c.areas.find((a) => a.id === "dns")!.state).toBe("not_applicable");
    expect(c).toMatchObject({ applicable: AREAS.length - 1, checked: AREAS.length - 2, complete: false });
  });
  it("NOT_APPLICABLE không chặn hạng A (website trên tên miền nền tảng vẫn có thể đạt A nếu mọi nhóm khác đã kiểm tra)", () => {
    const fs = full().filter((x) => x.ruleId !== "config.dns-email-security");
    fs.push(g("config.dns-email-security", "info", "na-platform"));
    expect(calculateScore(fs)).toMatchObject({ grade: "A", coverage: { complete: true } });
  });
  it("quét nhanh: chi tiết chứng chỉ là ‘ngoài phạm vi’, không phải ‘chưa kiểm tra được’", () => {
    const c = scanCoverage(full().filter((x) => x.ruleId !== "tls.certificate-expiry"), { quick: true });
    expect(c.areas.find((a) => a.id === "certificate")!.state).toBe("out_of_scope");
    expect(c.complete).toBe(false);
  });
});
