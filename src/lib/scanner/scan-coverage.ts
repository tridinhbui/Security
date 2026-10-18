import type { Finding } from "./types";

/**
 * ĐIỂM BẢO MẬT và PHẠM VI QUÉT là hai con số khác nhau.
 *  - Điểm: cấu hình quan sát được tốt đến đâu (score.ts).
 *  - Phạm vi: lượt quét này thực sự kiểm tra được bao nhiêu nhóm. Một website có thể được 95 điểm chỉ vì phần lớn kiểm tra không chạy được.
 *
 * Bốn loại kết quả cho mỗi phát hiện và mỗi nhóm:
 *  PASS (đạt) · FAIL (chưa đạt) · UNKNOWN (chưa kiểm tra được: thiếu dữ liệu) · NOT_APPLICABLE (không áp dụng cho website này).
 * NOT_APPLICABLE được lưu dưới dạng status "info" với khoá fingerprint bắt đầu bằng "na-" (giữ nguyên lược đồ CSDL, không cần migration).
 */
export type ResultClass = "pass" | "fail" | "unknown" | "not_applicable" | "info";

export const NA_KEY_PREFIX = "na-";
export function isNotApplicable(f: Pick<Finding, "status" | "fingerprint">): boolean {
  return f.status === "info" && (f.fingerprint.split("|")[1] ?? "").startsWith(NA_KEY_PREFIX);
}
export function resultClass(f: Pick<Finding, "status" | "fingerprint">): ResultClass {
  if (isNotApplicable(f)) return "not_applicable";
  return f.status === "pass" ? "pass" : f.status === "fail" ? "fail" : f.status === "unknown" ? "unknown" : "info";
}

/** Các nhóm kiểm tra cốt lõi. Mỗi nhóm có những luật luôn cho kết quả (đạt hoặc chưa đạt) khi có dữ liệu. */
export const AREAS = [
  { id: "transport", label: "HTTPS và chuyển hướng", rules: ["tls.https-available", "tls.http-to-https-redirect", "tls.hsts"] },
  { id: "certificate", label: "Chứng chỉ và phiên bản TLS", rules: ["tls.certificate-expiry", "tls.certificate-strength", "tls.protocol-version", "tls.cipher-suite"] },
  { id: "headers", label: "Header bảo mật và CSP", rules: ["headers.csp", "headers.frame-protection", "headers.x-content-type-options", "privacy.referrer-policy"] },
  { id: "cookies", label: "Cookie", rules: ["cookies.flags"] },
  { id: "cors", label: "CORS", rules: ["browser.cors"] },
  { id: "content", label: "Nội dung trang (mixed content, ghi chú, địa chỉ nội bộ)", rules: ["browser.mixed-content", "exposure.html-comments", "exposure.internal-references"] },
  { id: "dns", label: "DNS và email (SPF, DMARC, CAA)", rules: ["config.dns-email-security"] },
  { id: "files", label: "Tệp công khai (security.txt)", rules: ["exposure.security-txt"] },
] as const;
export type AreaId = (typeof AREAS)[number]["id"];
export type AreaState = "checked" | "unknown" | "not_applicable" | "out_of_scope";
export interface AreaCoverage { id: AreaId; label: string; state: AreaState }
export interface ScanCoverage {
  areas: AreaCoverage[];
  /** Số nhóm áp dụng được (trừ “không áp dụng”). */
  applicable: number;
  checked: number;
  /** checked / applicable, 0–100. */
  percent: number;
  /** true khi MỌI nhóm áp dụng được đều đã được kiểm tra. Chỉ khi đó điểm mới được xếp hạng A. */
  complete: boolean;
}

/** Quét nhanh không đọc chi tiết chứng chỉ (trừ khi đã có trong bộ nhớ đệm): nhóm đó “ngoài phạm vi”, không phải “lỗi”. */
const QUICK_OUT_OF_SCOPE: ReadonlySet<string> = new Set(["certificate"]);

export function scanCoverage(findings: Pick<Finding, "ruleId" | "status" | "fingerprint">[], opts: { quick?: boolean } = {}): ScanCoverage {
  const byRule = new Map<string, ResultClass[]>();
  for (const f of findings) byRule.set(f.ruleId, [...(byRule.get(f.ruleId) ?? []), resultClass(f)]);
  const areas: AreaCoverage[] = AREAS.map((a) => {
    const cls = a.rules.flatMap((r) => byRule.get(r) ?? []);
    const state: AreaState = cls.includes("not_applicable") && !cls.some((c) => c === "pass" || c === "fail")
      ? "not_applicable"
      : cls.some((c) => c === "pass" || c === "fail" || c === "info") ? "checked"
      : opts.quick && QUICK_OUT_OF_SCOPE.has(a.id) ? "out_of_scope"
      : "unknown";
    return { id: a.id, label: a.label, state };
  });
  const applicable = areas.filter((a) => a.state !== "not_applicable").length;
  const checked = areas.filter((a) => a.state === "checked").length;
  return { areas, applicable, checked, percent: applicable ? Math.round((checked / applicable) * 100) : 0, complete: checked === applicable };
}

export const AREA_STATE_LABEL: Record<AreaState, string> = {
  checked: "Đã kiểm tra", unknown: "Chưa kiểm tra được", not_applicable: "Không áp dụng", out_of_scope: "Ngoài phạm vi lượt quét này",
};
