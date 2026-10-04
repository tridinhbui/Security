import { CATEGORIES, type Category, type Confidence, type Finding, type Severity } from "./types";

/**
 * Score = 100 − Σ penalty over failing findings, where penalty = severity weight × confidence factor.
 * Passing, informational and "unknown" results never reduce the score.
 * Caps stop a pile of small passes from hiding a serious problem: any Critical finding caps
 * the score at 59 (F/D boundary), any High at 79 (no better than C).
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 3, info: 0 };
export const CONFIDENCE_FACTOR: Record<Confidence, number> = { high: 1, medium: 0.7, low: 0.4 };

export type Grade = "A" | "B" | "C" | "D" | "F";

export function penalty(f: Pick<Finding, "status" | "severity" | "confidence">): number {
  return f.status === "fail" ? SEVERITY_WEIGHT[f.severity] * CONFIDENCE_FACTOR[f.confidence] : 0;
}

export function gradeFor(score: number): Grade {
  return score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
}

export interface ScoreResult {
  score: number;
  grade: Grade;
  /** null when no check in the category produced a result. */
  categoryScores: Record<Category, number | null>;
  severityCounts: Record<Severity, number>;
  passed: number;
  failed: number;
}

export function calculateScore(findings: Finding[]): ScoreResult {
  const fails = findings.filter((f) => f.status === "fail");
  let total = 0;
  for (const f of findings) total += penalty(f);
  let score = Math.max(0, 100 - total);
  if (fails.some((f) => f.severity === "critical")) score = Math.min(score, 59);
  else if (fails.some((f) => f.severity === "high")) score = Math.min(score, 79);
  score = Math.round(score);

  const categoryScores = {} as Record<Category, number | null>;
  for (const c of CATEGORIES) {
    const inCat = findings.filter((f) => f.category === c && f.status !== "unknown");
    if (inCat.length === 0) {
      categoryScores[c] = null;
      continue;
    }
    // Category scores are intentionally harsher (×1.5): fewer checks per category.
    const p = inCat.reduce((a, f) => a + penalty(f), 0) * 1.5;
    categoryScores[c] = Math.round(Math.max(0, 100 - p));
  }

  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of fails) severityCounts[f.severity]++;
  // Informational notes are counted under "info" so the UI can show them.
  severityCounts.info += findings.filter((f) => f.status === "info").length;

  return { score, grade: gradeFor(score), categoryScores, severityCounts, passed: findings.filter((f) => f.status === "pass").length, failed: fails.length };
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const CONF_ORDER: Confidence[] = ["high", "medium", "low"];
const STATUS_ORDER = ["fail", "info", "unknown", "pass"];

/** Priority order for the findings list: failing first, by severity, then confidence. */
export function prioritize(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) ||
      SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
      CONF_ORDER.indexOf(a.confidence) - CONF_ORDER.indexOf(b.confidence) ||
      a.title.localeCompare(b.title),
  );
}

export function topRisks(findings: Finding[], n = 3): Finding[] {
  return prioritize(findings.filter((f) => f.status === "fail" && f.severity !== "info")).slice(0, n);
}

export const SCORE_DISCLAIMER =
  "Điểm số này là đánh giá cấu hình từ bên ngoài, dựa trên những gì trình duyệt của một khách truy cập có thể quan sát. Điểm cao không chứng minh website an toàn, và điểm thấp cũng không chứng minh website đã bị xâm nhập.";
