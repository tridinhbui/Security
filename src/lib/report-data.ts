import type { ReportData } from "@/components/Report";
import { rowToFinding, type ReportView } from "./db-types";
import type { PreviousComparison } from "./reports";
import { SCORE_DISCLAIMER } from "./scanner/score";
import type { Severity } from "./scanner/types";

export function toReportData(view: ReportView, opts: { variant: "owner" | "shared"; comparison?: PreviousComparison | null }): ReportData {
  const s = view.scan;
  return {
    id: s.id, url: s.normalized_url, host: s.host, scannedAt: s.completed_at ?? s.created_at, score: s.score ?? 0, grade: s.grade ?? "F",
    categoryScores: s.category_scores ?? {}, severityCounts: s.severity_counts ?? ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>),
    platforms: s.platforms ?? [], requestCount: s.request_count, findings: view.findings.map(rowToFinding), targets: opts.variant === "owner" ? view.targets : [],
    comparison: opts.comparison ? { previousScore: opts.comparison.comparison.previousScore, previousAt: opts.comparison.previous.completed_at ?? opts.comparison.previous.created_at, scoreDelta: opts.comparison.comparison.scoreDelta, newFindings: opts.comparison.comparison.newFindings, resolvedFindings: opts.comparison.comparison.resolvedFindings, unchanged: opts.comparison.comparison.unchanged } : null,
    canRescan: opts.variant === "owner", variant: opts.variant, disclaimer: SCORE_DISCLAIMER,
  };
}
