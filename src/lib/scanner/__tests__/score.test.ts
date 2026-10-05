import { describe, expect, it } from "vitest";
import { calculateScore, gradeFor, PASSIVE_SCORE_CEILING, penalty, prioritize, topRisks } from "../score";
import { makeFinding } from "../util";
import type { Finding, Severity, Confidence, FindingStatus } from "../types";

const f = (severity: Severity, confidence: Confidence = "high", status: FindingStatus = "fail", category: Finding["category"] = "Headers", id = `r.${Math.random()}`) =>
  makeFinding({ ruleId: id, title: `${severity} ${id}`, category, severity, confidence, status, summary: "s", explanation: "e" });

describe("scoring", () => {
  it("không bao giờ đạt 100: trần 96 cho quét thụ động, 90 khi phạm vi bị hạn chế", () => {
    const r = calculateScore([f("info", "high", "pass"), f("info", "high", "info")]);
    expect(r).toMatchObject({ score: 96, ceiling: 96, grade: "A", failed: 0, passed: 1 });
    expect(calculateScore([f("info", "high", "pass")], { limitedCoverage: true })).toMatchObject({ score: 90, ceiling: 90, grade: "A" });
    expect(PASSIVE_SCORE_CEILING).toBeLessThan(100);
  });
  it("trần áp dụng cho cả điểm theo nhóm", () => {
    const r = calculateScore([f("info", "high", "pass", "Headers")]);
    expect(r.categoryScores.Headers).toBe(96);
    expect(calculateScore([f("info", "high", "pass", "Headers")], { limitedCoverage: true }).categoryScores.Headers).toBe(90);
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
    const r = calculateScore([f("medium", "high", "fail", "Headers"), f("info", "high", "pass", "Transport Security")]);
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
