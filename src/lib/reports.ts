import { compareScans, type Comparison } from "./compare";
import { decrypt } from "./crypto";
import type { D1Like } from "./db/d1";
import { parseJson } from "./db/d1";
import * as repo from "./db/repo";
import { rowToFinding, type FindingRow, type ReportView, type ScanRow, type TargetView } from "./db-types";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATUS_RANK: Record<string, number> = { fail: 0, info: 1, unknown: 2, pass: 3 };
const CONF_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };

export function sortFindings(rows: FindingRow[]): FindingRow[] {
  return [...rows].sort((a, b) => STATUS_RANK[a.status]! - STATUS_RANK[b.status]! || SEV_RANK[a.severity]! - SEV_RANK[b.severity]! || CONF_RANK[a.confidence]! - CONF_RANK[b.confidence]! || a.title.localeCompare(b.title));
}

async function assemble(db: D1Like, scan: ScanRow, includeTargets: boolean): Promise<ReportView> {
  const findings = sortFindings(await repo.listFindings(db, scan.id));
  let targets: TargetView[] = [];
  if (includeTargets) {
    targets = await Promise.all((await repo.listTargetsRaw(db, scan.id)).map(async (t) => {
      let headers: TargetView["headers"] = null;
      try { headers = t.headers_enc ? JSON.parse(await decrypt(t.headers_enc)) : null; } catch { headers = null; }
      return { role: t.role, url: t.url, final_url: t.final_url, status_code: t.status_code, tls: parseJson(t.tls, null), headers, error_code: t.error_code };
    }));
  }
  return { scan, findings, targets };
}

/** Owner view. Returns null for scans the user does not own (ownership enforced in repo.getScan). */
export async function loadReport(db: D1Like, userId: string, scanId: string, opts: { includeTargets: boolean }): Promise<ReportView | null> {
  const scan = await repo.getScan(db, userId, scanId);
  return scan ? assemble(db, scan, opts.includeTargets) : null;
}

/** Public share view: caller must have validated the share token. Raw headers are never included. */
export async function loadSharedReport(db: D1Like, scanId: string): Promise<ReportView | null> {
  const scan = await repo.getScanInternal(db, scanId);
  return scan ? assemble(db, scan, false) : null;
}

export interface PreviousComparison { previous: ScanRow; comparison: Comparison }

/** Most recent earlier completed scan of the same URL by the same user (or an explicit one), diffed against `current`. */
export async function loadComparison(db: D1Like, current: ReportView, againstId?: string): Promise<PreviousComparison | null> {
  const s = current.scan;
  if (s.status !== "completed" || s.score === null) return null;
  const [prev] = await repo.earlierCompleted(db, s.user_id, s.normalized_url, s.created_at, 1, againstId);
  if (!prev || prev.score === null) return null;
  const prevFindings = (await repo.listFindings(db, prev.id)).map(rowToFinding);
  return { previous: prev, comparison: compareScans({ score: prev.score, findings: prevFindings }, { score: s.score, findings: current.findings.map(rowToFinding) }) };
}
