import { ScanBudget } from "../ssrf/budget";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "../ssrf/dns";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { createWorkerFetcher } from "../ssrf/worker-fetch";
import { collect } from "./collect-core";
import { createDohDnsLookup } from "./dns-doh";
import { evaluate } from "./evaluate";
import { ALL_RULES } from "./rules";
import { calculateScore, type Grade } from "./score";
import type { TlsInfo } from "../ssrf/types";
import type { Finding, Observations } from "./types";
import { attachFixCommands } from "./fixes";
import { OWASP_MAP } from "../guidance";
import { collectCookies } from "./rules/cookies";
import { header } from "./util";
import { IMPACT, urgencyFor, type Urgency } from "./impact";
import { ANALYST, originFor, reproFor, type Origin } from "./analyst";

/**
 * QUÉT NHANH MIỄN PHÍ (không cần tài khoản). Chạy hoàn toàn trong Worker, thụ động và rất nhẹ:
 *  - chỉ trang gốc của tên miền (không crawl, không chạy JS, không trình duyệt, không tải script ngoài);
 *  - ≤ 14 request, ≤ 2 MB, ≤ 12 giây; SSRF được kiểm tra ở mọi bước như quét đầy đủ (xem worker-fetch.ts);
 *  - chỉ chạy tập luật dưới đây.
 */
export const QUICK_RULES: Record<string, { group: QuickGroup }> = {
  "headers.x-content-type-options": { group: "headers" }, "headers.frame-protection": { group: "headers" }, "headers.broken": { group: "headers" },
  "privacy.referrer-policy": { group: "headers" }, "privacy.permissions-policy": { group: "headers" },
  "tls.https-available": { group: "https" }, "tls.hsts": { group: "https" }, "tls.certificate-expiry": { group: "https" },
  "tls.http-to-https-redirect": { group: "redirect" },
  "cookies.flags": { group: "cookies" },
  "headers.csp": { group: "csp" },
  "browser.cors": { group: "cors" },
  "config.dns-email-security": { group: "dns" },
  "config.server-disclosure": { group: "exposure" }, "exposure.error-page-disclosure": { group: "exposure" }, "exposure.html-comments": { group: "exposure" },
  "exposure.internal-references": { group: "exposure" }, "config.debug-headers": { group: "exposure" },
  "exposure.security-txt": { group: "securitytxt" },
  "browser.mixed-content": { group: "mixed" },
  "browser.third-party-integrity": { group: "sri" },
  // Phân tích sâu: chỉ dùng dữ liệu đã thu (không thêm request), dành cho người đọc chuyên môn
  "adv.csp-analysis": { group: "csp" }, "adv.header-consistency": { group: "headers" }, "headers.cache-policy": { group: "headers" }, "headers.deprecated": { group: "headers" },
  "headers.cross-origin-isolation": { group: "headers" }, "adv.shared-cache-leak": { group: "cookies" }, "adv.cookie-scope": { group: "cookies" }, "cookies.prefix": { group: "cookies" },
  "tls.cipher-suite": { group: "https" }, "tls.hsts-preload": { group: "https" }, "adv.certificate-hygiene": { group: "https" },
  "tls.www-consistency": { group: "redirect" }, "adv.redirect-chain": { group: "redirect" }, "config.suspicious-redirects": { group: "redirect" },
  "adv.spf-deep": { group: "dns" }, "adv.dmarc-deep": { group: "dns" }, "adv.supply-chain": { group: "sri" },
  "adv.form-method": { group: "mixed" }, "browser.form-targets": { group: "mixed" }, "tls.insecure-login-form": { group: "mixed" },
  "exposure.secrets": { group: "exposure" }, "exposure.public-config": { group: "exposure" }, "exposure.subdomain-takeover": { group: "exposure" },
  "exposure.outdated-libraries": { group: "exposure" }, "exposure.robots-txt": { group: "exposure" }, "exposure.sitemap-xml": { group: "exposure" },
};
export type QuickGroup = "headers" | "https" | "redirect" | "cookies" | "csp" | "cors" | "dns" | "exposure" | "securitytxt" | "mixed" | "sri";
export const GROUP_LABEL: Record<QuickGroup, string> = {
  headers: "Header bảo mật", https: "HTTPS / SSL", redirect: "Chuyển hướng HTTP → HTTPS", cookies: "Cookie", csp: "CSP", cors: "CORS",
  dns: "SPF / DMARC / CAA", exposure: "Lộ thông tin", securitytxt: "security.txt", mixed: "Nội dung hỗn hợp (mixed content)", sri: "Script bên ngoài / SRI",
};

export type QuickStatus = "pass" | "warning" | "fail";
/** Chi tiết kỹ thuật + giải pháp của một mục (chỉ dữ liệu đã được che; không bao giờ có giá trị cookie hay bí mật). */
export interface QuickTech {
  ruleId: string; severity: string; confidence: string; evidence: string[]; owasp: string[];
  /** Giải pháp: tóm tắt, các bước, và lệnh/cấu hình để dán. Rỗng với mục đã đạt. */
  fixSummary: string; fixSteps: string[]; fix: { label: string; language: string; code: string }[];
  references: { title: string; url: string }[];
  /** "Nếu để 1 ngày thì sao?" — chỉ có ở mục chưa đạt. */
  impact?: { today: string; worst: string; who: string; urgency: Urgency };
  /** Góc nhìn analyst: câu khẳng định + câu phụ, nguồn gốc lỗi, và lệnh chỉ-đọc để tự tái hiện. */
  statement?: string; sub?: string; origin?: Origin; repro?: string | null;
}
export interface QuickItem { id: string; group: QuickGroup; label: string; status: QuickStatus; text: string; tech?: QuickTech }
/** Dấu vân tay + bề mặt tấn công quan sát được (từ dữ liệu đã thu, không request thêm). */
export interface QuickRecon {
  server: string | null; poweredBy: string | null; platforms: string[]; technologies: string[]; addresses: string[]; httpVersion: string | null;
  tls: { protocol: string | null; cipher: string | null; issuer: string | null; subject: string | null; validTo: string | null; daysRemaining: number | null; keyType: string | null; keyBits: number | null; validityDays: number | null; sans: number | null } | null;
  dns: { ns: string[]; mx: string[]; caa: string[]; spf: string | null; dmarc: string | null; dnssec: boolean | null; mtaSts: boolean | null } | null;
  headers: { name: string; value: string | null }[]; cookies: { name: string; flags: string[] }[]; redirects: { status: number | null; url: string }[];
}
export interface QuickResult {
  host: string; score: number; grade: Grade; scannedAt: string; counts: Record<QuickStatus, number>; items: QuickItem[]; recon?: QuickRecon;
  /** Lượt quét nhanh có phạm vi giới hạn: điểm tối đa 90. */
  limited: true; requests: number;
}

const short = (s: string, n = 170) => (s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s);

/** Mức độ → Đạt / Cảnh báo / Lỗi. Chỉ Thấp là cảnh báo; Trung bình trở lên là lỗi. */
export function toStatus(f: Pick<Finding, "status" | "severity">): QuickStatus | null {
  if (f.status === "pass") return "pass";
  if (f.status !== "fail") return null; // ghi chú / chưa kiểm tra được: không hiển thị
  return f.severity === "low" || f.severity === "info" ? "warning" : "fail";
}

const clip = (x: string, n: number) => (x.length > n ? `${x.slice(0, n - 1)}…` : x);
export function toItems(findings: Finding[], host = ""): QuickItem[] {
  const out: QuickItem[] = [];
  for (const f of findings) {
    const meta = QUICK_RULES[f.ruleId];
    const status = toStatus(f);
    if (!meta || !status) continue;
    const bad = status !== "pass";
    const tech: QuickTech = {
      ruleId: f.ruleId, severity: f.severity, confidence: f.confidence,
      evidence: f.evidence.slice(0, 5).map((e) => clip(e, 220)),
      owasp: OWASP_MAP[f.ruleId] ?? [],
      fixSummary: bad ? clip(f.remediation?.summary ?? "", 260) : "",
      fixSteps: bad ? (f.remediation?.steps ?? []).slice(0, 4).map((x) => clip(x, 220)) : [],
      fix: bad ? (f.remediation?.snippets ?? []).slice(0, 4).map((x) => ({ label: clip(x.label, 90), language: x.language, code: clip(x.code, 900) })) : [],
      references: f.references.slice(0, 3),
      ...(bad && ANALYST[f.ruleId] ? { statement: ANALYST[f.ruleId]!.statement, sub: ANALYST[f.ruleId]!.sub, origin: originFor(f.ruleId, f.title), repro: host ? reproFor(f.ruleId, host) : null } : {}),
      ...(bad && IMPACT[f.ruleId] ? { impact: { today: IMPACT[f.ruleId]!.today, worst: IMPACT[f.ruleId]!.worst, who: IMPACT[f.ruleId]!.who, urgency: urgencyFor(f.ruleId, f.severity) } } : {}),
    };
    out.push({ id: f.fingerprint, group: meta.group, label: GROUP_LABEL[meta.group], status, text: short(status === "pass" ? f.summary : `${f.title}. ${f.summary}`), tech });
  }
  const order: Record<QuickStatus, number> = { fail: 0, warning: 1, pass: 2 };
  return out.sort((a, b) => order[a.status] - order[b.status] || a.label.localeCompare(b.label));
}

export interface QuickDeps {
  resolver: Resolver;
  fetchImpl?: typeof fetch;
  denyHosts?: string[];
  /** Thông tin TLS đã có sẵn trong bộ nhớ đệm (nếu có): giúp kiểm tra hạn chứng chỉ mà không phải gọi container. */
  tlsFor?: (host: string) => Promise<TlsInfo | null>;
}

const RECON_HEADERS = ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy", "cache-control", "access-control-allow-origin"];
export function buildRecon(obs: Observations): QuickRecon {
  const p = obs.page, t = obs.https?.tls, d = obs.dns;
  return {
    server: (p && header(p.headers, "server")) || null, poweredBy: (p && header(p.headers, "x-powered-by")) || null,
    platforms: obs.platforms, technologies: obs.technologies.slice(0, 12), addresses: (obs.https?.resolved ?? obs.http?.resolved ?? []).slice(0, 4),
    httpVersion: obs.legacyTls?.h2 === true ? "h2" : obs.legacyTls?.h2 === false ? "http/1.1" : null,
    tls: t ? { protocol: t.protocol, cipher: t.cipher, issuer: t.issuer ?? null, subject: t.subject ?? null, validTo: t.validTo ?? null, daysRemaining: t.daysRemaining ?? null, keyType: t.keyType ?? null, keyBits: t.keyBits ?? null, validityDays: t.validityDays ?? null, sans: t.altNames?.length ?? null } : null,
    dns: d ? { ns: (d.ns ?? []).slice(0, 6), mx: (d.mx ?? []).slice(0, 6), caa: (d.caa ?? []).slice(0, 4), spf: d.spf ? clip(d.spf, 200) : null, dmarc: d.dmarc ? clip(d.dmarc, 200) : null, dnssec: d.dnssec ?? null, mtaSts: d.mtaSts ?? null } : null,
    headers: RECON_HEADERS.map((n) => { const v = p ? header(p.headers, n) : undefined; return { name: n, value: v ? clip(v, 160) : null }; }),
    // Chỉ TÊN và cờ của cookie — không bao giờ có giá trị.
    cookies: collectCookies(obs).slice(0, 12).map((c) => ({ name: c.name, flags: [c.secure ? "Secure" : "", c.httpOnly ? "HttpOnly" : "", c.sameSite ? `SameSite=${c.sameSite}` : "", c.domain ? `Domain=${c.domain}` : "", c.path ? `Path=${c.path}` : ""].filter(Boolean) })),
    redirects: (obs.http?.chain ?? []).slice(0, 6).map((h) => ({ status: h.status, url: clip(h.url, 140) })),
  };
}

/** Ném SsrfError nếu mục tiêu không hợp lệ/không công khai. Không bao giờ ném lỗi mạng: lỗi được phản ánh trong kết quả. */
export async function runQuickScan(input: string, deps: QuickDeps): Promise<QuickResult> {
  const first = normalizeTargetUrl(input);
  const target = normalizeTargetUrl(`https://${first.host}/`); // chỉ trang gốc: bỏ đường dẫn/query người dùng nhập
  const dnsCache = new Map<string, { at: number; addrs: ResolvedAddress[] }>();
  await resolvePublicAddresses(target.host, deps.resolver, dnsCache);

  const budget = new ScanBudget(14, 2 * 1024 * 1024, 12_000);
  const fetch = createWorkerFetcher(budget, { resolver: deps.resolver, dnsCache, fetchImpl: deps.fetchImpl, denyHosts: deps.denyHosts });
  const obs = await collect(target, target.url, { fetch, budget, quick: true, lookupDns: createDohDnsLookup(deps.fetchImpl ?? globalThis.fetch) });

  const blocked = obs.https?.error?.blocked ? obs.https.error : obs.http?.error?.blocked ? obs.http.error : null;
  if (!obs.page && blocked) throw new SsrfError(blocked.code as SsrfError["code"], blocked.message, blocked.detail);

  if (obs.https && !obs.https.error && deps.tlsFor) {
    const tls = await deps.tlsFor(target.host).catch(() => null);
    if (tls) obs.https.tls = tls;
  }

  const rules = ALL_RULES.filter((r) => r.id in QUICK_RULES);
  const { findings } = evaluate(obs, rules);
  // HTTPS không dùng được (chứng chỉ hỏng, lỗi mạng…): luật tls.https-available báo; các luật phụ thuộc trang HTTP vẫn chạy trên bản HTTP nếu có.
  const score = calculateScore(findings.filter((f) => f.ruleId in QUICK_RULES), { limitedCoverage: true });
  const items = toItems(attachFixCommands(findings, { host: target.host, platforms: obs.platforms }), target.host);
  // Luật SRI im lặng khi không có gì để báo; với trang HTML đã phân tích được, hiển thị rõ là "đạt" thay vì bỏ trống mục này.
  if (obs.html && !items.some((i) => i.group === "sri")) items.push({ id: "sri-none", group: "sri", label: GROUP_LABEL.sri, status: "pass", text: "Không thấy script hay stylesheet từ CDN công cộng nào thiếu mã kiểm tra toàn vẹn (SRI)." });
  const counts = { pass: 0, warning: 0, fail: 0 } as Record<QuickStatus, number>;
  for (const i of items) counts[i.status]++;
  if (!obs.page) {
    // Không kết nối được: đừng trả điểm cao cho một website không tới được.
    return { host: target.host, score: 0, grade: "F", scannedAt: obs.scannedAt, counts: { pass: 0, warning: 0, fail: 1 }, requests: budget.used, limited: true,
      items: [{ id: "unreachable", group: "https", label: GROUP_LABEL.https, status: "fail", text: "Không kết nối được tới website qua HTTPS lẫn HTTP. Hãy kiểm tra địa chỉ và chắc chắn website đang hoạt động." }] };
  }
  return { host: target.host, score: score.score, grade: score.grade, scannedAt: obs.scannedAt, counts, items, limited: true, requests: budget.used, recon: buildRecon(obs) };
}
