import { isoAgo, newId, nowIso, type D1Like } from "./d1";

export type Verdict = "clear" | "unclear";
export interface VoteInput { voter: string; ruleId: string; variant: string; verdict: Verdict; source: "quick" | "full"; mode: string; comment: string }

/** Khoá biến thể chỉ chấp nhận dạng an toàn (vd "xfo", "hsts-no-maxage"); mọi thứ khác (có thể chứa tên miền) bị bỏ. */
export const cleanVariant = (v: unknown): string => (typeof v === "string" && /^[a-z0-9][a-z0-9-]{0,31}$/.test(v) ? v : "");
/**
 * Nhận xét tự do là kênh dễ rò rỉ nhất: người dùng hay dán nguyên tên miền, email, địa chỉ IP, token hay số điện thoại vào đó.
 * Mọi thứ trông như định danh bị thay bằng [đã ẩn] TRƯỚC khi lưu; ký tự điều khiển/đảo chiều chữ (Trojan-source) bị bỏ.
 */
const REDACT: RegExp[] = [
  /[a-z][a-z0-9+.-]*:\/\/\S+/gi,                                   // URL có giao thức
  /[\w.+-]+@[\w-]+(\.[\w-]+)+/g,                                   // email
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,                                  // IPv4
  /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi,                     // IPv6
  /(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|vn|info|biz|xyz|co|me|ai|cloud|online|site|shop|edu|gov|tech|store|uk|us|jp|kr|cn|de|fr|ru)\b(?:\/\S*)?/gi, // tên miền
  /\b(?:sk|pk|rk|ghp|gho|ghs|xox[abp]|AKIA|AIza|eyJ)[\w-]{8,}/g,          // tiền tố khoá/token quen thuộc
  /\b[A-Za-z0-9_\-+/=]{24,}\b/g,                                    // chuỗi dài giống token/hash
  /(?<!\w)\+?\d[\d\s().-]{8,}\d(?!\w)/g,                           // số điện thoại / dãy số dài
];
export const REDACTED = "[đã ẩn]";
export const cleanComment = (c: unknown): string => {
  if (typeof c !== "string") return "";
  let t = c.normalize("NFKC").replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, " ");
  for (const re of REDACT) t = t.replace(re, REDACTED);
  return t.replace(/\s+/g, " ").trim().slice(0, 300);
};
export const VOTES_PER_HOUR = 60;

/** Lưu (hoặc đổi) một phiếu. Trả false nếu vượt giới hạn tốc độ. */
export async function saveVote(db: D1Like, v: VoteInput): Promise<boolean> {
  const recent = (await db.prepare("SELECT COUNT(*) c FROM explain_feedback WHERE voter_hash = ? AND updated_at > ?").bind(v.voter, isoAgo(3_600_000)).first<{ c: number }>())?.c ?? 0;
  if (recent >= VOTES_PER_HOUR) return false;
  const now = nowIso();
  await db.prepare(`INSERT INTO explain_feedback (id,rule_id,variant,verdict,source,mode,comment,voter_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(voter_hash, rule_id, variant) DO UPDATE SET verdict=excluded.verdict, comment=excluded.comment, source=excluded.source, mode=excluded.mode, updated_at=excluded.updated_at`)
    .bind(newId(), v.ruleId, v.variant, v.verdict, v.source, v.mode.slice(0, 12), v.verdict === "unclear" ? v.comment : "", v.voter, now, now).run();
  return true;
}

/** Mẫu từ ít hơn mức này thì KHÔNG kết luận, chỉ hiển thị số liệu. */
export const MIN_VOTES = 10;
/** Cận dưới khoảng tin cậy Wilson 95% của tỉ lệ “chưa rõ”: tránh coi 2/2 phiếu là “100% chưa rõ”. */
export function unclearLowerBound(unclear: number, total: number): number {
  if (total <= 0) return 0;
  const z = 1.96, p = unclear / total, n = total;
  return Math.max(0, (p + (z * z) / (2 * n) - z * Math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n)) / (1 + (z * z) / n));
}
/** insufficient: chưa đủ phiếu · priority: đủ phiếu và tỉ lệ chưa rõ chắc chắn ≥ 30% · watch: đủ phiếu, có dấu hiệu · ok */
export type ClarityLevel = "insufficient" | "priority" | "watch" | "ok";
export function clarityLevel(unclear: number, total: number): ClarityLevel {
  if (total < MIN_VOTES) return "insufficient";
  const lb = unclearLowerBound(unclear, total);
  return lb >= 0.3 ? "priority" : unclear / total >= 0.25 ? "watch" : "ok";
}

export interface RuleClarity { rule_id: string; variant: string; clear: number; unclear: number; total: number }
/** Tổng hợp theo (luật, biến thể): mục nào bị đánh giá "chưa rõ" nhiều nhất lên đầu. */
export async function clarityByRule(db: D1Like, limit = 200): Promise<RuleClarity[]> {
  const { results } = await db.prepare(`SELECT rule_id, variant, SUM(verdict='clear') AS clear, SUM(verdict='unclear') AS unclear, COUNT(*) AS total
    FROM explain_feedback GROUP BY rule_id, variant ORDER BY unclear DESC, total DESC LIMIT ?`).bind(limit).all<RuleClarity>();
  return results;
}
export async function recentUnclearComments(db: D1Like, limit = 40) {
  const { results } = await db.prepare("SELECT rule_id, variant, comment, source, mode, updated_at FROM explain_feedback WHERE verdict='unclear' AND comment <> '' ORDER BY updated_at DESC LIMIT ?").bind(limit)
    .all<{ rule_id: string; variant: string; comment: string; source: string; mode: string; updated_at: string }>();
  return results;
}
