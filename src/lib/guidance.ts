import { ANALYST, originFor, reproFor } from "./scanner/analyst";
import { IMPACT, URGENCY_LABEL, urgencyFor } from "./scanner/impact";
import { CATEGORY_LABEL, SEV_LABEL } from "./i18n";
import { standardsFor } from "./standards";
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
  "adv.csp-analysis": "planned", "adv.shared-cache-leak": "quick", "adv.cookie-scope": "medium", "adv.supply-chain": "medium", "adv.dom-xss-flow": "planned", "adv.postmessage": "medium", "adv.web-storage-secrets": "medium", "adv.endpoint-map": "planned", "adv.graphql-surface": "quick", "adv.redirect-chain": "quick", "adv.header-consistency": "quick", "adv.spf-deep": "quick", "adv.dmarc-deep": "medium", "adv.certificate-hygiene": "quick", "adv.form-method": "quick",
  "tls.https-available": "medium", "tls.certificate-expiry": "quick", "tls.certificate-strength": "medium", "tls.protocol-version": "quick",
  "tls.http2": "quick", "tls.http-to-https-redirect": "quick", "tls.www-consistency": "quick", "tls.hsts": "quick", "tls.insecure-login-form": "medium",
  "headers.csp": "planned", "headers.frame-protection": "quick", "headers.x-content-type-options": "quick", "headers.broken": "quick",
  "headers.cross-origin-isolation": "planned", "headers.charset": "quick", "headers.deprecated": "quick", "tls.hsts-preload": "planned", "tls.cipher-suite": "quick", "headers.cache-policy": "quick", "config.debug-headers": "quick", "config.http-methods": "quick", "browser.form-targets": "medium", "cookies.prefix": "medium", "exposure.internal-references": "medium", "exposure.html-comments": "quick",
  "browser.mixed-content": "medium", "browser.third-party-integrity": "medium", "browser.cors": "medium",
  "cookies.flags": "medium", "cookies.cache-control-sensitive": "quick",
  "exposure.secrets": "quick", "exposure.public-config": "medium", "exposure.source-maps": "quick", "exposure.robots-txt": "quick", "exposure.sitemap-xml": "quick",
  "exposure.security-txt": "quick", "exposure.outdated-libraries": "planned", "exposure.subdomain-takeover": "quick", "exposure.error-page-disclosure": "medium",
  "config.server-disclosure": "quick", "config.technology": "quick", "config.auth-surface": "medium", "config.suspicious-redirects": "medium", "config.dns-email-security": "medium",
  "privacy.referrer-policy": "quick", "privacy.permissions-policy": "quick", "privacy.trackers": "medium", "privacy.third-party-origins": "medium",
};
export const effortFor = (f: Pick<Finding, "ruleId">): Effort => EFFORT[f.ruleId] ?? "medium";

/**
 * Ánh xạ sang OWASP Top 10:2025 (bản chính thức, thay cho 2021). Đối chiếu với tên hạng mục và danh sách CWE của từng hạng mục trong
 * repo OWASP/Top10 (2025/docs/en). Ánh xạ theo Ý NGHĨA của kiểm tra; luật không thuộc rủi ro nào trong Top 10 (hiệu năng, thông tin
 * tham khảo, quyền riêng tư) cố ý không có mục: tls.http2, exposure.robots-txt, exposure.sitemap-xml, exposure.security-txt,
 * config.technology, config.auth-surface, adv.endpoint-map, privacy.trackers, privacy.third-party-origins.
 */
export const OWASP_MAP: Record<string, string[]> = {
  "tls.https-available": ["A04:2025 – Lỗi mật mã học"],
  "tls.certificate-expiry": ["A04:2025 – Lỗi mật mã học"],
  "tls.certificate-strength": ["A04:2025 – Lỗi mật mã học"],
  "tls.protocol-version": ["A04:2025 – Lỗi mật mã học"],
  "tls.http-to-https-redirect": ["A04:2025 – Lỗi mật mã học"],
  "tls.www-consistency": ["A04:2025 – Lỗi mật mã học"],
  "tls.hsts": ["A04:2025 – Lỗi mật mã học"],
  "tls.hsts-preload": ["A04:2025 – Lỗi mật mã học"],
  "tls.cipher-suite": ["A04:2025 – Lỗi mật mã học"],
  "browser.mixed-content": ["A04:2025 – Lỗi mật mã học"],
  "adv.certificate-hygiene": ["A04:2025 – Lỗi mật mã học"],
  "adv.redirect-chain": ["A04:2025 – Lỗi mật mã học"],
  "tls.insecure-login-form": ["A04:2025 – Lỗi mật mã học", "A07:2025 – Lỗi xác thực"],
  "headers.csp": ["A05:2025 – Injection (giảm thiểu XSS)", "A02:2025 – Cấu hình bảo mật sai"],
  "adv.csp-analysis": ["A05:2025 – Injection (giảm thiểu XSS)"],
  "adv.dom-xss-flow": ["A05:2025 – Injection (giảm thiểu XSS)"],
  "headers.frame-protection": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.x-content-type-options": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.broken": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.cross-origin-isolation": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.charset": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.deprecated": ["A02:2025 – Cấu hình bảo mật sai"],
  "config.debug-headers": ["A02:2025 – Cấu hình bảo mật sai"],
  "config.http-methods": ["A02:2025 – Cấu hình bảo mật sai"],
  "config.server-disclosure": ["A02:2025 – Cấu hình bảo mật sai"],
  "config.dns-email-security": ["A02:2025 – Cấu hình bảo mật sai"],
  "exposure.internal-references": ["A02:2025 – Cấu hình bảo mật sai"],
  "exposure.html-comments": ["A02:2025 – Cấu hình bảo mật sai"],
  "exposure.public-config": ["A02:2025 – Cấu hình bảo mật sai"],
  "exposure.source-maps": ["A02:2025 – Cấu hình bảo mật sai"],
  "exposure.subdomain-takeover": ["A02:2025 – Cấu hình bảo mật sai"],
  "adv.graphql-surface": ["A02:2025 – Cấu hình bảo mật sai"],
  "adv.header-consistency": ["A02:2025 – Cấu hình bảo mật sai"],
  "adv.spf-deep": ["A02:2025 – Cấu hình bảo mật sai"],
  "adv.dmarc-deep": ["A02:2025 – Cấu hình bảo mật sai"],
  "privacy.referrer-policy": ["A02:2025 – Cấu hình bảo mật sai"],
  "privacy.permissions-policy": ["A02:2025 – Cấu hình bảo mật sai"],
  "headers.cache-policy": ["A06:2025 – Thiết kế không an toàn"],
  "cookies.cache-control-sensitive": ["A06:2025 – Thiết kế không an toàn"],
  "adv.shared-cache-leak": ["A06:2025 – Thiết kế không an toàn"],
  "adv.cookie-scope": ["A07:2025 – Lỗi xác thực"],
  "cookies.prefix": ["A07:2025 – Lỗi xác thực"],
  "browser.form-targets": ["A07:2025 – Lỗi xác thực"],
  "browser.third-party-integrity": ["A08:2025 – Lỗi toàn vẹn phần mềm và dữ liệu"],
  "browser.cors": ["A01:2025 – Kiểm soát truy cập bị hỏng", "A02:2025 – Cấu hình bảo mật sai"],
  "adv.postmessage": ["A01:2025 – Kiểm soát truy cập bị hỏng"],
  "adv.web-storage-secrets": ["A01:2025 – Kiểm soát truy cập bị hỏng"],
  "exposure.outdated-libraries": ["A03:2025 – Lỗi chuỗi cung ứng phần mềm"],
  "config.suspicious-redirects": ["A04:2025 – Lỗi mật mã học", "A02:2025 – Cấu hình bảo mật sai"],
  "exposure.error-page-disclosure": ["A10:2025 – Xử lý sai tình huống bất thường", "A02:2025 – Cấu hình bảo mật sai"],
  "adv.supply-chain": ["A03:2025 – Lỗi chuỗi cung ứng phần mềm", "A08:2025 – Lỗi toàn vẹn phần mềm và dữ liệu"],
  "cookies.flags": ["A02:2025 – Cấu hình bảo mật sai", "A07:2025 – Lỗi xác thực"],
  "exposure.secrets": ["A07:2025 – Lỗi xác thực", "A02:2025 – Cấu hình bảo mật sai"],
  "adv.form-method": ["A06:2025 – Thiết kế không an toàn", "A07:2025 – Lỗi xác thực"],
};

const open = (fs: Finding[]) => fs.filter((f) => f.status === "fail" && f.severity !== "info");

export interface RoadmapGroup { effort: Effort; items: Finding[]; /** Điểm ước tính tăng thêm nếu xử lý hết nhóm này. */ gain: number }

/** Nhóm các phát hiện cần xử lý theo mức công sức; mỗi nhóm kèm điểm ước tính sẽ tăng. */
export function buildRoadmap(findings: Finding[], currentScore: number): RoadmapGroup[] {
  const failing = open(findings);
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (["quick", "medium", "planned"] as Effort[]).map((effort) => {
    const items = failing.filter((f) => effortFor(f) === effort).sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    // Coi các mục đã xử lý là ĐẠT (không xoá đi): xoá sẽ làm nhóm kiểm tra trông như “chưa kiểm tra được” và hạ trần điểm sai.
    const remaining = findings.map((f) => (items.includes(f) ? { ...f, status: "pass" as const } : f));
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
    const an = ANALYST[f.ruleId], im = IMPACT[f.ruleId];
    L.push(`### ${i + 1}. [${SEV_LABEL[f.severity]}] ${an?.statement ?? f.title}`, "");
    if (an) L.push(`_${an.sub}_`, "", `- Nguồn gốc: **${originFor(f.ruleId, f.title).label}** — quy trình đang thiếu: ${originFor(f.ruleId, f.title).rootCause}`, `- Mức khẩn cấp: **${URGENCY_LABEL[urgencyFor(f.ruleId, f.severity)]}**`);
    if (im) L.push(`- Trong 1 ngày: ${im.today}`, `- Trường hợp xấu nhất: ${im.worst}`, `- Ai khai thác được: ${im.who}`);
    L.push("", `**Chúng tôi phát hiện:** ${f.summary}`, "", `**Vì sao quan trọng:** ${f.explanation}`, "");
    const rp = an ? reproFor(f.ruleId, a.host) : null;
    if (rp) L.push("**Tự tái hiện (chỉ đọc):**", "", "```bash", rp, "```", "");
    const std = standardsFor(f.ruleId);
    const refs = [...(OWASP_MAP[f.ruleId] ?? []).map((o) => o.split(" – ")[0]!), ...std.cwe.map((c) => `CWE-${c}`), ...std.asvs.map((x) => `ASVS ${x}`), ...std.wstg];
    if (refs.length) L.push(`**Chuẩn tham chiếu:** ${refs.join(" · ")}`, "");
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
