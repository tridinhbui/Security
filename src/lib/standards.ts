import type { Finding } from "./scanner/types";

/**
 * Ánh xạ từng luật sang chuẩn tham chiếu quốc tế: CWE (MITRE), OWASP ASVS 4.0.3 và OWASP WSTG (Web Security Testing Guide).
 * Cùng với OWASP Top 10 (2021) trong guidance.ts. Đây là ánh xạ GẦN NHẤT về ý nghĩa của kiểm tra, không phải tuyên bố tuân thủ:
 * quét thụ động từ bên ngoài không thể chứng minh một yêu cầu ASVS được đáp ứng đầy đủ.
 */
export interface Standards { cwe: number[]; asvs: string[]; wstg: string[] }
const S = (cwe: number[], asvs: string[], wstg: string[]): Standards => ({ cwe, asvs, wstg });

export const STANDARDS: Record<string, Standards> = {
  // ---- truyền tải & TLS
  "tls.https-available": S([319], ["9.1.1"], ["WSTG-CRYP-03"]),
  "tls.certificate-expiry": S([298], ["9.2.1"], ["WSTG-CRYP-01"]),
  "tls.certificate-strength": S([326], ["9.1.2"], ["WSTG-CRYP-01"]),
  "tls.protocol-version": S([326], ["9.1.3"], ["WSTG-CRYP-01"]),
  "tls.http2": S([], [], []),
  "tls.http-to-https-redirect": S([319], ["9.1.1"], ["WSTG-CONF-07"]),
  "tls.www-consistency": S([319], ["9.1.1"], ["WSTG-CONF-07"]),
  "tls.hsts": S([319], ["14.4.5"], ["WSTG-CONF-07"]),
  "tls.hsts-preload": S([319], ["14.4.5"], ["WSTG-CONF-07"]),
  "tls.cipher-suite": S([327], ["9.1.2"], ["WSTG-CRYP-01"]),
  "tls.insecure-login-form": S([319], ["9.1.1"], ["WSTG-CRYP-03"]),
  // ---- header
  "headers.csp": S([79], ["14.4.3"], ["WSTG-CONF-12"]),
  "headers.frame-protection": S([1021], ["14.4.7"], ["WSTG-CLNT-09"]),
  "headers.x-content-type-options": S([693], ["14.4.4"], ["WSTG-CONF-14"]),
  "headers.broken": S([693], ["14.4.1"], ["WSTG-CONF-14"]),
  "headers.cross-origin-isolation": S([693], [], ["WSTG-CONF-14"]),
  "headers.charset": S([116], ["14.4.1"], ["WSTG-CONF-14"]),
  "headers.deprecated": S([693], ["14.4.3"], ["WSTG-CONF-14"]),
  "headers.cache-policy": S([524], ["8.2.1"], ["WSTG-ATHN-06"]),
  // ---- trình duyệt
  "browser.mixed-content": S([319], ["9.1.1"], ["WSTG-CRYP-03"]),
  "browser.third-party-integrity": S([829], ["14.2.3"], []),
  "browser.cors": S([942], ["14.5.3"], ["WSTG-CLNT-07"]),
  "browser.form-targets": S([319], ["9.1.1"], ["WSTG-CRYP-03"]),
  // ---- cookie & phiên
  "cookies.flags": S([614, 1004, 1275], ["3.4.1", "3.4.2", "3.4.3"], ["WSTG-SESS-02"]),
  "cookies.prefix": S([565], ["3.4.4"], ["WSTG-SESS-02"]),
  "cookies.cache-control-sensitive": S([524], ["8.2.1"], ["WSTG-ATHN-06"]),
  // ---- lộ thông tin
  "exposure.secrets": S([798, 200], ["2.10.4"], ["WSTG-INFO-05"]),
  "exposure.public-config": S([200], [], ["WSTG-INFO-05"]),
  "exposure.source-maps": S([540], [], ["WSTG-INFO-05"]),
  "exposure.robots-txt": S([200], [], ["WSTG-INFO-03"]),
  "exposure.sitemap-xml": S([], [], ["WSTG-INFO-03"]),
  "exposure.security-txt": S([], [], []),
  "exposure.outdated-libraries": S([1104], ["14.2.1"], ["WSTG-INFO-08"]),
  "exposure.subdomain-takeover": S([], [], ["WSTG-CONF-10"]),
  "exposure.error-page-disclosure": S([209], ["7.4.1"], ["WSTG-ERRH-01"]),
  "exposure.internal-references": S([200], [], ["WSTG-INFO-05"]),
  "exposure.html-comments": S([615], [], ["WSTG-INFO-05"]),
  // ---- cấu hình
  "config.server-disclosure": S([200], ["14.3.3"], ["WSTG-INFO-02"]),
  "config.technology": S([], [], ["WSTG-INFO-08"]),
  "config.suspicious-redirects": S([601], ["5.1.5"], ["WSTG-CLNT-04"]),
  "config.dns-email-security": S([], [], []),
  "config.auth-surface": S([], [], []),
  "config.debug-headers": S([215], ["14.3.2"], ["WSTG-CONF-02"]),
  "config.http-methods": S([749], ["14.5.1"], ["WSTG-CONF-06"]),
  // ---- quyền riêng tư
  "privacy.referrer-policy": S([200], ["14.4.6"], []),
  "privacy.permissions-policy": S([693], [], []),
  "privacy.third-party-origins": S([], [], []),
  "privacy.trackers": S([], [], []),
  // ---- nâng cao
  "adv.csp-analysis": S([79], ["14.4.3"], ["WSTG-CONF-12"]),
  "adv.shared-cache-leak": S([524, 525], ["8.2.1"], ["WSTG-ATHN-06"]),
  "adv.cookie-scope": S([613, 565], ["3.3.2", "3.4.5"], ["WSTG-SESS-02"]),
  "adv.supply-chain": S([829, 494], ["14.2.3", "14.2.4"], []),
  "adv.dom-xss-flow": S([79], ["5.3.3"], ["WSTG-CLNT-01"]),
  "adv.postmessage": S([346], [], ["WSTG-CLNT-11"]),
  "adv.web-storage-secrets": S([922], [], ["WSTG-CLNT-12"]),
  "adv.endpoint-map": S([200], [], ["WSTG-INFO-06"]),
  "adv.graphql-surface": S([200], ["13.4.1"], ["WSTG-APIT-01"]),
  "adv.redirect-chain": S([319], ["9.1.1"], ["WSTG-CONF-07"]),
  "adv.header-consistency": S([693], ["14.4.3", "14.4.4"], ["WSTG-CONF-14"]),
  "adv.spf-deep": S([], [], []),
  "adv.dmarc-deep": S([], [], []),
  "adv.certificate-hygiene": S([295], ["9.2.1"], ["WSTG-CRYP-01"]),
  "adv.form-method": S([598], ["8.3.1"], ["WSTG-CRYP-03"]),
};

export const standardsFor = (ruleId: string): Standards => STANDARDS[ruleId] ?? { cwe: [], asvs: [], wstg: [] };

export const cweUrl = (id: number) => `https://cwe.mitre.org/data/definitions/${id}.html`;
export const wstgUrl = (id: string) => `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/#${id.toLowerCase()}`;
export const ASVS_URL = "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x00-Header.md";

/** OWASP Top 10 (2021): mức độ mà quét thụ động từ bên ngoài có thể đánh giá. */
export const OWASP_TOP10: { code: string; name: string; reach: "good" | "partial" | "none"; note: string }[] = [
  { code: "A01", name: "Kiểm soát truy cập bị hỏng", reach: "partial", note: "Chỉ thấy CORS và chuyển hướng; không thử quyền truy cập thật." },
  { code: "A02", name: "Lỗi mật mã học", reach: "good", note: "HTTPS/TLS, chứng chỉ, HSTS, cookie, khoá bí mật bị lộ." },
  { code: "A03", name: "Injection", reach: "partial", note: "Chỉ đánh giá lớp giảm thiểu XSS (CSP) và dấu hiệu DOM XSS; không gửi payload." },
  { code: "A04", name: "Thiết kế không an toàn", reach: "partial", note: "Chính sách cache, rò rỉ phiên qua cache dùng chung." },
  { code: "A05", name: "Cấu hình bảo mật sai", reach: "good", note: "Header, trang lỗi, lộ phiên bản, debug, DNS/email." },
  { code: "A06", name: "Thành phần lỗi thời", reach: "partial", note: "Phát hiện thư viện phía trình duyệt cũ; không thấy phần mềm phía máy chủ." },
  { code: "A07", name: "Lỗi xác thực", reach: "partial", note: "Cờ cookie phiên, form mật khẩu; không thử đăng nhập." },
  { code: "A08", name: "Lỗi toàn vẹn phần mềm & dữ liệu", reach: "partial", note: "SRI, chuỗi cung ứng script bên thứ ba." },
  { code: "A09", name: "Lỗi ghi nhật ký & giám sát", reach: "none", note: "Không thể thấy từ bên ngoài." },
  { code: "A10", name: "Giả mạo yêu cầu phía máy chủ (SSRF)", reach: "none", note: "Cần gửi payload nên bị loại trừ có chủ đích (quét không khai thác)." },
];

export interface CoverageRow { code: string; name: string; reach: "good" | "partial" | "none"; note: string; checks: number; failing: number; passing: number }

/** Độ phủ OWASP Top 10: mỗi hạng mục có bao nhiêu kiểm tra đã chạy, đang lỗi, đang đạt. Đếm theo luật (một luật lỗi ở đâu đó thì tính là lỗi). */
export function owaspCoverage(findings: Finding[], owaspMap: Record<string, string[]>): CoverageRow[] {
  const byRule = new Map<string, "fail" | "pass">();
  for (const f of findings) {
    if (f.status !== "pass" && f.status !== "fail") continue;
    if (f.status === "fail" && f.severity === "info") continue;
    if (byRule.get(f.ruleId) === "fail") continue;
    byRule.set(f.ruleId, f.status);
  }
  return OWASP_TOP10.map((t) => {
    let failing = 0, passing = 0;
    for (const [rule, st] of byRule) {
      if (!(owaspMap[rule] ?? []).some((c) => c.startsWith(t.code))) continue;
      if (st === "fail") failing++; else passing++;
    }
    return { ...t, checks: failing + passing, failing, passing };
  });
}
