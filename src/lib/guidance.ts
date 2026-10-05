import { CATEGORY_LABEL, SEV_LABEL } from "./i18n";
import { calculateScore, gradeFor, penalty, SEVERITY_WEIGHT, CONFIDENCE_FACTOR } from "./scanner/score";
import { CATEGORIES, type Finding, type Severity } from "./scanner/types";

/**
 * Lớp trình bày: mức công sức khắc phục, ánh xạ OWASP, tóm tắt điều hành, xuất Markdown.
 * Thuần hàm — không I/O — nên chạy được cả ở Worker lẫn trình duyệt.
 */

export type Effort = "quick" | "medium" | "planned";

export const EFFORT_LABEL: Record<Effort, { title: string; hint: string }> = {
  quick: { title: "Làm ngay", hint: "Dưới 15 phút, chủ yếu là sửa cấu hình" },
  medium: { title: "Trong tuần này", hint: "Cần sửa mã hoặc thay đổi hạ tầng nhỏ" },
  planned: { title: "Lên kế hoạch", hint: "Cần thử nghiệm kỹ hoặc thay đổi lớn hơn" },
};

/** Mức công sức mặc định theo luật; luật không có trong bảng được coi là "medium". */
export const EFFORT: Record<string, Effort> = {
  "tls.https-available": "medium", "tls.certificate-expiry": "quick", "tls.certificate-strength": "medium", "tls.protocol-version": "quick",
  "tls.http2": "quick", "tls.http-to-https-redirect": "quick", "tls.www-consistency": "quick", "tls.hsts": "quick", "tls.insecure-login-form": "medium",
  "headers.csp": "planned", "headers.frame-protection": "quick", "headers.x-content-type-options": "quick", "headers.broken": "quick",
  "headers.cross-origin-isolation": "planned", "headers.charset": "quick", "headers.deprecated": "quick",
  "browser.mixed-content": "medium", "browser.third-party-integrity": "medium", "browser.cors": "medium",
  "cookies.flags": "medium", "cookies.cache-control-sensitive": "quick",
  "exposure.secrets": "quick", "exposure.public-config": "medium", "exposure.source-maps": "quick", "exposure.robots-txt": "quick", "exposure.sitemap-xml": "quick",
  "exposure.security-txt": "quick", "exposure.outdated-libraries": "planned", "exposure.subdomain-takeover": "quick", "exposure.error-page-disclosure": "medium",
  "config.server-disclosure": "quick", "config.technology": "quick", "config.auth-surface": "medium", "config.suspicious-redirects": "medium", "config.dns-email-security": "medium",
  "privacy.referrer-policy": "quick", "privacy.permissions-policy": "quick", "privacy.trackers": "medium", "privacy.third-party-origins": "medium",
};
export const effortFor = (f: Pick<Finding, "ruleId">): Effort => EFFORT[f.ruleId] ?? "medium";

/** Ánh xạ sang OWASP Top 10 (2021). */
export const OWASP_MAP: Record<string, string[]> = {
  "tls.https-available": ["A02:2021 – Lỗi mật mã học"], "tls.certificate-expiry": ["A02:2021 – Lỗi mật mã học"], "tls.certificate-strength": ["A02:2021 – Lỗi mật mã học"],
  "tls.protocol-version": ["A02:2021 – Lỗi mật mã học"], "tls.http-to-https-redirect": ["A02:2021 – Lỗi mật mã học"], "tls.www-consistency": ["A02:2021 – Lỗi mật mã học"],
  "tls.hsts": ["A02:2021 – Lỗi mật mã học"], "tls.insecure-login-form": ["A02:2021 – Lỗi mật mã học", "A07:2021 – Lỗi xác thực"],
  "headers.csp": ["A03:2021 – Injection (giảm thiểu XSS)", "A05:2021 – Cấu hình bảo mật sai"], "headers.frame-protection": ["A05:2021 – Cấu hình bảo mật sai"],
  "headers.x-content-type-options": ["A05:2021 – Cấu hình bảo mật sai"], "headers.broken": ["A05:2021 – Cấu hình bảo mật sai"], "headers.cross-origin-isolation": ["A05:2021 – Cấu hình bảo mật sai"],
  "headers.charset": ["A05:2021 – Cấu hình bảo mật sai"], "headers.deprecated": ["A05:2021 – Cấu hình bảo mật sai"],
  "browser.mixed-content": ["A02:2021 – Lỗi mật mã học"], "browser.third-party-integrity": ["A08:2021 – Lỗi toàn vẹn phần mềm và dữ liệu"], "browser.cors": ["A01:2021 – Kiểm soát truy cập bị hỏng", "A05:2021 – Cấu hình bảo mật sai"],
  "cookies.flags": ["A07:2021 – Lỗi xác thực", "A02:2021 – Lỗi mật mã học"], "cookies.cache-control-sensitive": ["A04:2021 – Thiết kế không an toàn"],
  "exposure.secrets": ["A02:2021 – Lỗi mật mã học", "A05:2021 – Cấu hình bảo mật sai"], "exposure.public-config": ["A05:2021 – Cấu hình bảo mật sai"], "exposure.source-maps": ["A05:2021 – Cấu hình bảo mật sai"],
  "exposure.outdated-libraries": ["A06:2021 – Thành phần lỗi thời hoặc có lỗ hổng"], "exposure.subdomain-takeover": ["A05:2021 – Cấu hình bảo mật sai"], "exposure.error-page-disclosure": ["A05:2021 – Cấu hình bảo mật sai"],
  "config.server-disclosure": ["A05:2021 – Cấu hình bảo mật sai"], "config.suspicious-redirects": ["A01:2021 – Kiểm soát truy cập bị hỏng"], "config.dns-email-security": ["A05:2021 – Cấu hình bảo mật sai"],
};

const open = (fs: Finding[]) => fs.filter((f) => f.status === "fail" && f.severity !== "info");

export interface RoadmapGroup { effort: Effort; items: Finding[]; /** Điểm ước tính tăng thêm nếu xử lý hết nhóm này. */ gain: number }

/** Nhóm các phát hiện cần xử lý theo mức công sức; mỗi nhóm kèm điểm ước tính sẽ tăng. */
export function buildRoadmap(findings: Finding[], currentScore: number): RoadmapGroup[] {
  const failing = open(findings);
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (["quick", "medium", "planned"] as Effort[]).map((effort) => {
    const items = failing.filter((f) => effortFor(f) === effort).sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    const remaining = findings.filter((f) => !items.includes(f));
    return { effort, items, gain: items.length ? Math.max(0, calculateScore(remaining).score - currentScore) : 0 };
  }).filter((g) => g.items.length > 0);
}

const LEVEL = (s: number) => (s >= 90 ? "rất tốt" : s >= 80 ? "tốt" : s >= 70 ? "khá" : s >= 60 ? "cần cải thiện" : "yếu");

/** Tóm tắt điều hành bằng tiếng Việt, sinh bằng mẫu cố định (không dùng AI). */
export function buildSummary(a: { host: string; score: number; grade: string; findings: Finding[]; categoryScores: Record<string, number | null> }): string[] {
  const fails = open(a.findings);
  const c = (s: Severity) => fails.filter((f) => f.severity === s).length;
  const paras: string[] = [];
  paras.push(`${a.host} đạt ${a.score}/100 điểm (hạng ${a.grade}) — mức ${LEVEL(a.score)} về cấu hình bảo mật nhìn từ bên ngoài.`);
  if (fails.length === 0) {
    paras.push("Không phát hiện vấn đề cần xử lý ở mức Thấp trở lên trong phạm vi các kiểm tra thụ động. Hãy tiếp tục quét định kỳ, nhất là sau mỗi lần thay đổi hạ tầng.");
    return paras;
  }
  const parts = [c("critical") && `${c("critical")} nghiêm trọng`, c("high") && `${c("high")} cao`, c("medium") && `${c("medium")} trung bình`, c("low") && `${c("low")} thấp`].filter(Boolean);
  paras.push(`Có ${fails.length} vấn đề cần xử lý: ${parts.join(", ")}.`);
  if (c("critical") + c("high") > 0) paras.push(`Ưu tiên số một: ${fails.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 2).map((f) => f.title).join("; ")}.`);
  const scored = CATEGORIES.map((k) => [k, a.categoryScores[k]] as const).filter((x): x is readonly [typeof CATEGORIES[number], number] => typeof x[1] === "number");
  if (scored.length > 1) {
    const worst = [...scored].sort((x, y) => x[1] - y[1])[0]!;
    if (worst[1] < 100) paras.push(`Nhóm yếu nhất là “${CATEGORY_LABEL[worst[0]]}” (${worst[1]}/100).`);
  }
  const quick = buildRoadmap(a.findings, a.score).find((g) => g.effort === "quick");
  if (quick) paras.push(`Có ${quick.items.length} việc có thể làm trong dưới 15 phút${quick.gain ? `; làm xong ước tính tăng khoảng ${quick.gain} điểm` : ""}.`);
  return paras;
}

/** Bảng trọng số dùng để giải thích cách tính điểm. */
export function scoringTable() {
  return (Object.keys(SEVERITY_WEIGHT) as Severity[]).map((s) => ({ severity: s, label: SEV_LABEL[s], weight: SEVERITY_WEIGHT[s] }));
}
export { CONFIDENCE_FACTOR, gradeFor, penalty };

/** Xuất báo cáo dạng Markdown (để dán vào tài liệu/ticket). */
export function toMarkdown(a: { url: string; host: string; scannedAt: string; score: number; grade: string; findings: Finding[]; categoryScores: Record<string, number | null>; disclaimer: string }): string {
  const L: string[] = [];
  L.push(`# Báo cáo bảo mật — ${a.host}`, "", `- URL: ${a.url}`, `- Thời điểm quét: ${a.scannedAt}`, `- Điểm: **${a.score}/100** (hạng **${a.grade}**)`, "");
  L.push("## Tóm tắt", "", ...buildSummary(a).map((p) => `${p}\n`));
  L.push("## Điểm theo nhóm", "", "| Nhóm | Điểm |", "|---|---|");
  for (const k of CATEGORIES) L.push(`| ${CATEGORY_LABEL[k]} | ${a.categoryScores[k] ?? "—"} |`);
  const fails = open(a.findings);
  L.push("", `## Vấn đề cần xử lý (${fails.length})`, "");
  fails.forEach((f, i) => {
    L.push(`### ${i + 1}. [${SEV_LABEL[f.severity]}] ${f.title}`, "", `**Chúng tôi phát hiện:** ${f.summary}`, "", `**Vì sao quan trọng:** ${f.explanation}`, "");
    if (f.evidence.length) L.push("**Bằng chứng:**", "", "```", ...f.evidence, "```", "");
    if (f.remediation) {
      L.push(`**Cách khắc phục:** ${f.remediation.summary}`, "");
      f.remediation.steps?.forEach((s) => L.push(`- ${s}`));
      if (f.remediation.steps?.length) L.push("");
      for (const s of f.remediation.snippets) L.push(`*${s.label}*`, "", "```" + s.language, s.code, "```", "");
    }
  });
  const passed = a.findings.filter((f) => f.status === "pass");
  L.push(`## Các kiểm tra đạt (${passed.length})`, "", ...passed.map((f) => `- ${f.title}`), "", "---", "", `_${a.disclaimer}_`, "");
  return L.join("\n");
}
