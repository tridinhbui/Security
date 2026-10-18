/**
 * Tổng hợp phiếu quan sát user testing (CSV do người quan sát điền). Thuần hàm: không tự sinh dữ liệu, không suy rộng.
 * Với ≤ 5 người chỉ báo SỐ ĐẾM (vd. 3/5), không báo phần trăm và không kết luận thống kê.
 */
export const COLUMNS = ["participant_id", "group", "task", "finding_rule", "completed", "seconds", "understanding", "owner_correct", "fix_found", "verify_known", "clarity_vote", "confusion_note"] as const;
export type Col = (typeof COLUMNS)[number];
export type Row = Record<Col, string>;
export const TASKS = ["T1", "T2", "T3", "T4", "T5"] as const;

export function parseCsv(text: string): Row[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#"));
  if (lines.length === 0) return [];
  const split = (l: string): string[] => { const out: string[] = []; let cur = "", q = false; for (let i = 0; i < l.length; i++) { const c = l[i]!; if (q) { if (c === '"' && l[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; } else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c; } out.push(cur); return out; };
  const head = split(lines[0]!).map((h) => h.trim());
  const missing = COLUMNS.filter((c) => !head.includes(c));
  if (missing.length) throw new Error(`Thiếu cột: ${missing.join(", ")}`);
  return lines.slice(1).map((l) => { const v = split(l); return Object.fromEntries(COLUMNS.map((c) => [c, (v[head.indexOf(c)] ?? "").trim()])) as Row; });
}

const num = (s: string) => (s === "" || Number.isNaN(Number(s)) ? null : Number(s));
const median = (a: number[]) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2; };
const mean = (a: number[]) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);

export interface TaskStat { task: string; n: number; completed: number; medianSeconds: number | null; meanUnderstanding: number | null }
export interface RuleStat { rule: string; n: number; meanUnderstanding: number | null; unclearVotes: number; wrongOwner: number; fixNotFound: number; notes: string[]; flag: "fix-first" | "review" | "ok" | "insufficient" }
export interface Summary { participants: number; groups: Record<string, number>; tasks: TaskStat[]; rules: RuleStat[]; caveats: string[]; invalid: string[] }

const FLAG_ORDER: Record<RuleStat["flag"], number> = { "fix-first": 0, review: 1, insufficient: 2, ok: 3 };

export function summarize(rows: Row[]): Summary {
  const invalid: string[] = [];
  const ok = rows.filter((r, i) => {
    const bad = !r.participant_id ? "thiếu participant_id" : !TASKS.includes(r.task as never) ? `task không hợp lệ "${r.task}"` : !["A", "B", "C"].includes(r.group) ? `group không hợp lệ "${r.group}"` : r.completed !== "" && !["0", "1"].includes(r.completed) ? "completed phải là 0/1" : (["understanding", "owner_correct", "fix_found"] as Col[]).some((c) => r[c] !== "" && !["0", "1", "2"].includes(r[c])) ? "điểm phải là 0/1/2" : null;
    if (bad) invalid.push(`dòng ${i + 2}: ${bad}`);
    return !bad;
  });
  const people = new Map<string, string>();
  for (const r of ok) people.set(r.participant_id, r.group);
  const groups: Record<string, number> = {};
  for (const g of people.values()) groups[g] = (groups[g] ?? 0) + 1;

  const tasks = TASKS.map((t) => {
    const rs = ok.filter((r) => r.task === t);
    return { task: t, n: new Set(rs.map((r) => r.participant_id)).size, completed: new Set(rs.filter((r) => r.completed === "1").map((r) => r.participant_id)).size, medianSeconds: median(rs.map((r) => num(r.seconds)).filter((x): x is number => x !== null)), meanUnderstanding: mean(rs.map((r) => num(r.understanding)).filter((x): x is number => x !== null)) };
  });

  const byRule = new Map<string, Row[]>();
  for (const r of ok) if (r.finding_rule) byRule.set(r.finding_rule, [...(byRule.get(r.finding_rule) ?? []), r]);
  const rules: RuleStat[] = [...byRule].map(([rule, rs]): RuleStat => {
    const n = new Set(rs.map((r) => r.participant_id)).size;
    const mu = mean(rs.map((r) => num(r.understanding)).filter((x): x is number => x !== null));
    const unclearVotes = rs.filter((r) => r.clarity_vote === "unclear").length, wrongOwner = rs.filter((r) => r.owner_correct === "0").length, fixNotFound = rs.filter((r) => r.fix_found === "0").length;
    const bad = (mu !== null && mu < 1) || wrongOwner >= 2 || fixNotFound >= 2 || unclearVotes >= 2;
    const weak = (mu !== null && mu < 1.5) || wrongOwner >= 1 || fixNotFound >= 1 || unclearVotes >= 1;
    return { rule, n, meanUnderstanding: mu, unclearVotes, wrongOwner, fixNotFound, notes: rs.map((r) => r.confusion_note).filter(Boolean), flag: n < 2 ? "insufficient" : bad ? "fix-first" : weak ? "review" : "ok" };
  }).sort((a, b) => FLAG_ORDER[a.flag] - FLAG_ORDER[b.flag]);

  const caveats = [`Mẫu ${people.size} người: chỉ dùng để tìm chỗ gây nhầm, không suy ra tỉ lệ của người dùng nói chung.`];
  if (people.size < 5) caveats.push(`Mới ${people.size}/5 người tham gia: kế hoạch chưa hoàn tất.`);
  if (!(groups["A"] ?? 0)) caveats.push("Chưa có người nhóm A (không kỹ thuật): không đánh giá được mục tiêu chính.");
  if (!(groups["C"] ?? 0)) caveats.push("Chưa có người nhóm C (chuyên môn bảo mật): chưa ai kiểm tra độ chính xác kỹ thuật của lời giải thích; không coi là đã được rà soát.");
  return { participants: people.size, groups, tasks, rules, caveats, invalid };
}
