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
import type { Finding } from "./types";

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
};
export type QuickGroup = "headers" | "https" | "redirect" | "cookies" | "csp" | "cors" | "dns" | "exposure" | "securitytxt" | "mixed" | "sri";
export const GROUP_LABEL: Record<QuickGroup, string> = {
  headers: "Header bảo mật", https: "HTTPS / SSL", redirect: "Chuyển hướng HTTP → HTTPS", cookies: "Cookie", csp: "CSP", cors: "CORS",
  dns: "SPF / DMARC / CAA", exposure: "Lộ thông tin", securitytxt: "security.txt", mixed: "Nội dung hỗn hợp (mixed content)", sri: "Script bên ngoài / SRI",
};

export type QuickStatus = "pass" | "warning" | "fail";
export interface QuickItem { id: string; group: QuickGroup; label: string; status: QuickStatus; text: string }
export interface QuickResult {
  host: string; score: number; grade: Grade; scannedAt: string; counts: Record<QuickStatus, number>; items: QuickItem[];
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

export function toItems(findings: Finding[]): QuickItem[] {
  const out: QuickItem[] = [];
  for (const f of findings) {
    const meta = QUICK_RULES[f.ruleId];
    const status = toStatus(f);
    if (!meta || !status) continue;
    out.push({ id: f.fingerprint, group: meta.group, label: GROUP_LABEL[meta.group], status, text: short(status === "pass" ? f.summary : `${f.title}. ${f.summary}`) });
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
  const items = toItems(findings);
  // Luật SRI im lặng khi không có gì để báo; với trang HTML đã phân tích được, hiển thị rõ là "đạt" thay vì bỏ trống mục này.
  if (obs.html && !items.some((i) => i.group === "sri")) items.push({ id: "sri-none", group: "sri", label: GROUP_LABEL.sri, status: "pass", text: "Không thấy script hay stylesheet từ CDN công cộng nào thiếu mã kiểm tra toàn vẹn (SRI)." });
  const counts = { pass: 0, warning: 0, fail: 0 } as Record<QuickStatus, number>;
  for (const i of items) counts[i.status]++;
  if (!obs.page) {
    // Không kết nối được: đừng trả điểm cao cho một website không tới được.
    return { host: target.host, score: 0, grade: "F", scannedAt: obs.scannedAt, counts: { pass: 0, warning: 0, fail: 1 }, requests: budget.used, limited: true,
      items: [{ id: "unreachable", group: "https", label: GROUP_LABEL.https, status: "fail", text: "Không kết nối được tới website qua HTTPS lẫn HTTP. Hãy kiểm tra địa chỉ và chắc chắn website đang hoạt động." }] };
  }
  return { host: target.host, score: score.score, grade: score.grade, scannedAt: obs.scannedAt, counts, items, limited: true, requests: budget.used };
}
