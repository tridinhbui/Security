import { isoAgo, newId, nowIso, type D1Like } from "./d1";

export type Verdict = "clear" | "unclear";
export interface VoteInput { voter: string; ruleId: string; variant: string; verdict: Verdict; source: "quick" | "full"; mode: string; comment: string }

/** Khoá biến thể chỉ chấp nhận dạng an toàn (vd "xfo", "hsts-no-maxage"); mọi thứ khác (có thể chứa tên miền) bị bỏ. */
export const cleanVariant = (v: unknown): string => (typeof v === "string" && /^[a-z0-9][a-z0-9-]{0,31}$/.test(v) ? v : "");
export const cleanComment = (c: unknown): string => (typeof c === "string" ? c.replace(/\s+/g, " ").trim().slice(0, 300) : "");
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
