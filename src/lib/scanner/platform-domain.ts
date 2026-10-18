import { getDomain, getPublicSuffix } from "tldts";

/**
 * Website chạy trên tên miền con của một nền tảng (ví dụ app.vercel.app, x.workers.dev, user.github.io, site.netlify.app)?
 * Dựa trên phần “private” của Public Suffix List: khi hậu tố công khai kể cả phần private khác hậu tố ICANN, tên miền gốc
 * thuộc về nền tảng chứ không thuộc chủ website. Trả về hậu tố nền tảng (vd. "vercel.app") hoặc null.
 *
 * Hệ quả: các bản ghi DNS của tên miền gốc (SPF, DMARC, CAA, DNSSEC, MX…) là của NỀN TẢNG; chủ website không thêm/sửa được,
 * nên không được báo là lỗi của họ.
 */
export function platformSuffix(host: string): string | null {
  const withPrivate = getPublicSuffix(host, { allowPrivateDomains: true });
  const icann = getPublicSuffix(host);
  if (!withPrivate || !icann || withPrivate === icann) return null;
  return host === withPrivate ? null : withPrivate;
}

/** Tên miền mà các kiểm tra DNS/email thực sự tra cứu (tên miền đăng ký được, vd. shop.example.com.vn → example.com.vn). Dùng chung cho lời giải thích và lệnh sửa để không lệch với điều đã kiểm tra. */
export function dnsApex(host: string): string {
  return getDomain(host) ?? host.replace(/^www\./, "");
}

/**
 * Đuôi tên miền mà TOÀN BỘ đã nằm trong danh sách HSTS cài sẵn của trình duyệt (danh sách preload của Chromium, được Chrome, Edge,
 * Firefox và Safari dùng chung): trình duyệt luôn tự đổi http:// thành https:// với mọi tên miền có đuôi này, kể cả lần truy cập đầu.
 * Danh sách cố ý bảo thủ: chỉ các đuôi do Google Registry công bố là được preload toàn bộ.
 */
const HSTS_PRELOADED_TLDS = new Set(["app", "dev", "page", "new", "day", "foo", "mov", "zip", "ing", "meme", "phd", "prof", "esq", "dad", "boo", "nexus"]);
export function hstsPreloadedTld(host: string): string | null {
  const tld = host.toLowerCase().replace(/\.$/, "").split(".").pop() ?? "";
  return HSTS_PRELOADED_TLDS.has(tld) ? tld : null;
}
