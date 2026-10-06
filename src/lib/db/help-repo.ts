import type { Severity } from "../scanner/types";
import { isoAgo, newId, nowIso, parseJson, type D1Like } from "./d1";

export type HelpStatus = "new" | "quoted" | "in_progress" | "done" | "cancelled";
export type HelpKind = "website" | "code" | "system" | "launch";
export interface HelpIssue { title: string; severity: Severity; group: string; source: string | null; evidence: string[] }
export interface HelpRequestRow {
  id: string; user_id: string; source_kind: HelpKind; source_id: string; label: string; issues: HelpIssue[]; note: string; contact: string;
  status: HelpStatus; quote: string; created_at: string; updated_at: string; email?: string;
}
export const HELP_STATUS_LABEL: Record<HelpStatus, string> = { new: "Đã gửi", quoted: "Đã có báo giá", in_progress: "Đang xử lý", done: "Hoàn tất", cancelled: "Đã huỷ" };
export const HELP_NOTE_MAX = 1000, HELP_QUOTE_MAX = 2000;

const toRow = (r: Record<string, unknown>): HelpRequestRow => ({ ...(r as unknown as HelpRequestRow), issues: parseJson<HelpIssue[]>(r.issues, []) });

export async function createHelpRequest(db: D1Like, a: { userId: string; kind: HelpKind; sourceId: string; label: string; issues: HelpIssue[]; note: string; contact: string }): Promise<string> {
  const id = newId(), now = nowIso();
  await db.prepare("INSERT INTO help_requests (id,user_id,source_kind,source_id,label,issues,note,contact,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .bind(id, a.userId, a.kind, a.sourceId, a.label.slice(0, 120), JSON.stringify(a.issues), a.note.slice(0, HELP_NOTE_MAX), a.contact.slice(0, 120), now, now).run();
  return id;
}
export async function countRecentHelp(db: D1Like, userId: string, windowMs: number): Promise<number> {
  return (await db.prepare("SELECT COUNT(*) c FROM help_requests WHERE user_id = ? AND created_at > ?").bind(userId, isoAgo(windowMs)).first<{ c: number }>())?.c ?? 0;
}
/** Luôn lọc theo user_id. */
export async function listMyHelp(db: D1Like, userId: string): Promise<HelpRequestRow[]> {
  const { results } = await db.prepare("SELECT * FROM help_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 30").bind(userId).all();
  return results.map(toRow);
}
export async function cancelMyHelp(db: D1Like, userId: string, id: string): Promise<boolean> {
  const r = await db.prepare("UPDATE help_requests SET status='cancelled', updated_at=? WHERE id=? AND user_id=? AND status IN ('new','quoted')").bind(nowIso(), id, userId).run();
  return (r.meta.changes ?? 0) > 0;
}
/** Chỉ cho quản trị viên (kiểm tra ở route/trang). */
export async function adminListHelp(db: D1Like): Promise<HelpRequestRow[]> {
  const { results } = await db.prepare("SELECT h.*, u.email FROM help_requests h JOIN users u ON u.id = h.user_id ORDER BY (h.status IN ('new','quoted','in_progress')) DESC, h.created_at DESC LIMIT 200").all();
  return results.map(toRow);
}
export async function adminUpdateHelp(db: D1Like, id: string, status: HelpStatus, quote: string): Promise<boolean> {
  const r = await db.prepare("UPDATE help_requests SET status=?, quote=?, updated_at=? WHERE id=? AND status != 'cancelled'").bind(status, quote.slice(0, HELP_QUOTE_MAX), nowIso(), id).run();
  return (r.meta.changes ?? 0) > 0;
}
export async function adminCountNewHelp(db: D1Like): Promise<number> {
  return (await db.prepare("SELECT COUNT(*) c FROM help_requests WHERE status = 'new'").first<{ c: number }>())?.c ?? 0;
}
