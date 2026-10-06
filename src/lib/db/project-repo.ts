import type { ProjectItem, LaunchVerdict } from "../project/types";
import type { Severity } from "../scanner/types";
import { isoIn, newId, nowIso, parseJson, type D1Like } from "./d1";

export type ProjectKind = "code" | "system" | "launch";

export interface ProjectScanRow {
  id: string; user_id: string; kind: ProjectKind; label: string; stack: string | null; score: number | null; grade: "A" | "B" | "C" | "D" | "F" | null;
  verdict: LaunchVerdict | null; severity_counts: Record<Severity, number>; items: ProjectItem[]; meta: Record<string, unknown>; created_at: string; expires_at: string;
}

function toRow(r: Record<string, unknown>): ProjectScanRow {
  return { ...(r as unknown as ProjectScanRow), severity_counts: parseJson(r.severity_counts, {} as Record<Severity, number>), items: parseJson<ProjectItem[]>(r.items, []), meta: parseJson<Record<string, unknown>>(r.meta, {}) };
}

export interface NewProjectScan { userId: string; kind: ProjectKind; label: string; stack?: string | null; score: number; grade: string; verdict?: LaunchVerdict | null; counts: Record<string, number>; items: ProjectItem[]; meta?: Record<string, unknown>; retentionDays: number }

export async function insertProjectScan(db: D1Like, p: NewProjectScan): Promise<string> {
  const id = newId();
  await db.prepare(`INSERT INTO project_scans (id,user_id,kind,label,stack,score,grade,verdict,severity_counts,items,meta,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(id, p.userId, p.kind, p.label.slice(0, 120), p.stack ?? null, p.score, p.grade, p.verdict ?? null, JSON.stringify(p.counts), JSON.stringify(p.items), JSON.stringify(p.meta ?? {}), nowIso(), isoIn(p.retentionDays * 86_400_000)).run();
  return id;
}

/** Luôn lọc theo user_id: D1 không có row-level security. */
export async function getProjectScan(db: D1Like, userId: string, id: string): Promise<ProjectScanRow | null> {
  const r = await db.prepare("SELECT * FROM project_scans WHERE id = ? AND user_id = ?").bind(id, userId).first();
  return r ? toRow(r) : null;
}

export async function listProjectScans(db: D1Like, userId: string, kind: ProjectKind, limit: number): Promise<ProjectScanRow[]> {
  const { results } = await db.prepare("SELECT * FROM project_scans WHERE user_id = ? AND kind = ? ORDER BY created_at DESC LIMIT ?").bind(userId, kind, limit).all();
  return results.map(toRow);
}

/** Lượt mới nhất của cùng mục tiêu (cùng nhãn), tuỳ chọn trước một thời điểm. */
export async function latestByLabel(db: D1Like, userId: string, kind: ProjectKind, label: string, before?: string): Promise<ProjectScanRow | null> {
  const r = await db.prepare(`SELECT * FROM project_scans WHERE user_id = ? AND kind = ? AND label = ? ${before ? "AND created_at < ?" : ""} ORDER BY created_at DESC LIMIT 1`)
    .bind(...(before ? [userId, kind, label, before] : [userId, kind, label])).first();
  return r ? toRow(r) : null;
}

export async function deleteProjectScan(db: D1Like, userId: string, id: string): Promise<boolean> {
  const r = await db.prepare("DELETE FROM project_scans WHERE id = ? AND user_id = ?").bind(id, userId).run();
  return (r.meta.changes ?? 0) > 0;
}
