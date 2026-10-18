import { CATEGORIES, type Category, type Confidence, type Finding, type Severity } from "./types";
import { scanCoverage, type ScanCoverage } from "./scan-coverage";

/**
 * Score = 100 − Σ penalty over failing findings, where penalty = severity weight × confidence factor.
 * Passing, informational and "unknown" results never reduce the score.
 * Caps stop a pile of small passes from hiding a serious problem: any Critical finding caps
 * the score at 59 (F/D boundary), any High at 79 (no better than C).
 *
 * Trần điểm: một lượt quét THỤ ĐỘNG không thể chứng minh website an toàn tuyệt đối (không thấy logic nghiệp vụ, phân quyền, lỗi ứng dụng),
 * nên điểm tối đa là PASSIVE_SCORE_CEILING. Khi phạm vi quét bị hạn chế (quét nhanh, chạm giới hạn request/thời gian) trần thấp hơn nữa.
 */
export const PASSIVE_SCORE_CEILING = 96;
/** Trần khi phạm vi quét không đầy đủ (quét nhanh, chạm giới hạn, thiếu dữ liệu ở một nhóm kiểm tra): 89, tức là KHÔNG BAO GIỜ được hạng A. */
export const LIMITED_COVERAGE_CEILING = 89;
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
  /** Điểm tối đa có thể đạt được trong lượt quét này. */
  ceiling: number;
  /** Phạm vi quét: tách khỏi điểm bảo mật. Hạng A chỉ khi phạm vi đầy đủ. */
  coverage: ScanCoverage;
  /** null when no check in the category produced a result. */
  categoryScores: Record<Category, number | null>;
  severityCounts: Record<Severity, number>;
  passed: number;
  failed: number;
}

/**
 * NGUYÊN NHÂN GỐC: một số luật phân tích sâu (adv.*) soi lại đúng cấu hình mà luật cơ bản đã báo (vd. 'unsafe-inline' trong CSP được cả
 * headers.csp và adv.csp-analysis báo). Mỗi nguyên nhân gốc chỉ bị trừ điểm MỘT lần (khoản nặng nhất trong nhóm) và chỉ khoản đó được
 * tính trần điểm; các phát hiện còn lại vẫn hiển thị như bằng chứng bổ sung.
 */
export function rootCause(f: Pick<Finding, "ruleId" | "fingerprint">): string {
  const key = f.fingerprint.split("|")[1] ?? "";
  switch (f.ruleId) {
    case "headers.csp": case "adv.csp-analysis": return "csp";
    case "adv.form-method": return "password-form-get";
    case "tls.insecure-login-form": return key === "method-get" ? "password-form-get" : f.fingerprint;
    case "adv.redirect-chain": return "redirect-chain";
    case "config.suspicious-redirects": return /^(downgrade|long):/.test(key) ? "redirect-chain" : f.fingerprint;
    case "adv.spf-deep": return "spf";
    case "adv.dmarc-deep": return "dmarc";
    case "config.dns-email-security": return key.startsWith("spf") ? "spf" : key.startsWith("dmarc") ? "dmarc" : f.fingerprint;
    case "adv.certificate-hygiene": return "cert-lifetime";
    case "tls.certificate-strength": return key === "long-validity" ? "cert-lifetime" : f.fingerprint;
    case "adv.shared-cache-leak": return "shared-cache-cookie";
    case "headers.cache-policy": return key === "cookie-cacheable" ? "shared-cache-cookie" : f.fingerprint;
    default: return f.fingerprint;
  }
}

/** Khoản trừ thực tế của từng phát hiện (theo fingerprint) sau khi gộp nguyên nhân gốc, và phát hiện nào là bản trùng của phát hiện nào. */
export function effectivePenalties(findings: Finding[]): { penalty: Map<string, number>; duplicateOf: Map<string, string> } {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    if (f.status !== "fail") continue;
    const r = rootCause(f), cur = best.get(r);
    if (!cur || penalty(f) > penalty(cur)) best.set(r, f);
  }
  const out = new Map<string, number>(), dup = new Map<string, string>();
  for (const f of findings) {
    if (f.status !== "fail") { out.set(f.fingerprint, 0); continue; }
    const owner = best.get(rootCause(f))!;
    if (owner === f) out.set(f.fingerprint, penalty(f));
    else { out.set(f.fingerprint, 0); dup.set(f.fingerprint, owner.title); }
  }
  return { penalty: out, duplicateOf: dup };
}

export function calculateScore(findings: Finding[], opts: { limitedCoverage?: boolean; quick?: boolean } = {}): ScoreResult {
  const coverage = scanCoverage(findings, { quick: opts.quick });
  // Thiếu bất kỳ nhóm kiểm tra áp dụng được nào → trần 89: một lượt quét không đầy đủ không được trông như hạng A.
  const ceiling = opts.limitedCoverage || !coverage.complete ? LIMITED_COVERAGE_CEILING : PASSIVE_SCORE_CEILING;
  const fails = findings.filter((f) => f.status === "fail");
  const eff = effectivePenalties(findings);
  const counted = fails.filter((f) => !eff.duplicateOf.has(f.fingerprint));
  let total = 0;
  for (const f of findings) total += eff.penalty.get(f.fingerprint) ?? 0;
  let score = Math.max(0, 100 - total);
  if (counted.some((f) => f.severity === "critical")) score = Math.min(score, 59);
  else if (counted.some((f) => f.severity === "high")) score = Math.min(score, 79);
  score = Math.round(Math.min(score, ceiling));

  const categoryScores = {} as Record<Category, number | null>;
  for (const c of CATEGORIES) {
    const inCat = findings.filter((f) => f.category === c && f.status !== "unknown");
    if (inCat.length === 0) {
      categoryScores[c] = null;
      continue;
    }
    // Category scores are intentionally harsher (×1.5): fewer checks per category.
    const p = inCat.reduce((a, f) => a + (eff.penalty.get(f.fingerprint) ?? 0), 0) * 1.5;
    categoryScores[c] = Math.round(Math.min(ceiling, Math.max(0, 100 - p)));
  }

  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of fails) severityCounts[f.severity]++;
  // Informational notes are counted under "info" so the UI can show them.
  severityCounts.info += findings.filter((f) => f.status === "info").length;

  return { score, grade: gradeFor(score), ceiling, coverage, categoryScores, severityCounts, passed: findings.filter((f) => f.status === "pass").length, failed: fails.length };
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

/** Việc nên làm trước: mỗi nguyên nhân gốc chỉ xuất hiện một lần (không để 2/3 vị trí ưu tiên cùng nói về một chỗ CSP). */
export function topRisks(findings: Finding[], n = 3): Finding[] {
  const seen = new Set<string>();
  return prioritize(findings.filter((f) => f.status === "fail" && f.severity !== "info")).filter((f) => { const r = rootCause(f); if (seen.has(r)) return false; seen.add(r); return true; }).slice(0, n);
}

export const SCORE_DISCLAIMER =
  "Điểm số này là đánh giá cấu hình từ bên ngoài, dựa trên những gì trình duyệt của một khách truy cập có thể quan sát. Không website nào đạt 100: quét thụ động không thấy được logic nghiệp vụ, phân quyền hay lỗi trong ứng dụng, nên điểm tối đa là 96 (90 khi phạm vi quét bị hạn chế). Điểm cao không chứng minh website an toàn, và điểm thấp cũng không chứng minh website đã bị xâm nhập.";
