import { ScanRefusedError } from "./report";
import { NO_TLS_CODES } from "./rules/transport";
import { header } from "./util";
import type { Observations } from "./types";

/**
 * PHẠM VI THỰC TẾ của một lượt quét. Khi một nhóm kiểm tra không có dữ liệu (HTTPS không kết nối ổn định, không đọc được chứng chỉ,
 * không tra được DNS…), các luật liên quan im lặng hoặc báo “chưa kiểm tra được” — đúng, vì không được biến thiếu dữ liệu thành lỗi.
 * Nhưng điểm khi đó KHÔNG được trông như điểm của một lượt quét đầy đủ: pipeline hạ trần điểm và báo rõ phần nào chưa kiểm tra được.
 */
export interface CoverageGap { code: string; text: string }

export function coverageGaps(obs: Observations, opts: { quick?: boolean } = {}): CoverageGap[] {
  const g: CoverageGap[] = [];
  const h = obs.https;
  if (h?.error && !h.error.blocked && !NO_TLS_CODES.has(h.error.code))
    g.push({ code: "https_unverified", text: `Không kết nối ổn định được bản HTTPS (${h.error.code}), nên các kiểm tra chứng chỉ, HSTS và header trên HTTPS chưa đầy đủ.` });
  else if (!opts.quick && h && !h.error && !h.tls)
    g.push({ code: "tls_unread", text: "Không đọc được thông tin chứng chỉ TLS (hạn dùng, độ dài khoá, phiên bản TLS), nên các mục này chưa được kiểm tra." });
  const dnsFailed = !!obs.dns && obs.dns.spf === undefined && obs.dns.dmarc === undefined; // mọi truy vấn TXT đều lỗi
  if ((!obs.dns || dnsFailed) && !obs.platformSuffix)
    g.push({ code: "dns_unavailable", text: "Không tra được DNS của tên miền, nên SPF, DMARC, CAA, DNSSEC chưa được kiểm tra." });
  return g;
}

/** Mã trạng thái và dấu hiệu cho thấy trang chủ là trang chặn của tường lửa/chống bot, không phải website thật. */
const BLOCK_STATUS = new Set([401, 403, 429, 503]);
export function blockedPage(obs: Observations): { status: number; reason: string } | null {
  const p = obs.page;
  if (!p || p.status === null) return null;
  const challenge = header(p.headers, "cf-mitigated") === "challenge" || /<title>\s*(Just a moment|Attention Required|Access denied)/i.test(p.body.slice(0, 4000));
  if (!challenge && !BLOCK_STATUS.has(p.status)) return null;
  return { status: p.status, reason: challenge ? "trang kiểm tra chống bot" : `mã ${p.status}` };
}

/**
 * Trang chủ trả về trang chặn (403, 429, 503, trang “Just a moment…” của tường lửa…): header và nội dung khi đó là của TƯỜNG LỬA, không phải
 * của website. Chấm điểm trên đó sẽ cho kết luận sai (cả lỗi giả lẫn đạt giả), nên từ chối chấm điểm và nói rõ cách xử lý.
 */
export function refuseIfBlocked(obs: Observations): void {
  const b = blockedPage(obs);
  if (!b) return;
  throw new ScanRefusedError("blocked_page", `Chưa quét được: trang chủ trả về ${b.reason}, thường do tường lửa hoặc chống bot chặn công cụ tự động. Những gì VibeSec nhìn thấy là trang chặn chứ không phải website của bạn, nên chúng tôi không chấm điểm để tránh kết luận sai. Nếu đây là website của bạn: tạm cho phép VibeSecBot trong cài đặt tường lửa (vd. Cloudflare → Security → WAF/Bots) rồi quét lại.`);
}
