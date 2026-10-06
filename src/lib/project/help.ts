import { rowToFinding } from "../db-types";
import type { D1Like } from "../db/d1";
import type { HelpIssue, HelpKind } from "../db/help-repo";
import { getProjectScan } from "../db/project-repo";
import * as repo from "../db/repo";
import { websiteItems } from "./launch";
import { bySeverity, type ProjectItem } from "./types";

export interface HelpSource { kind: HelpKind; id: string; label: string; items: ProjectItem[] }

/** Tải đúng báo cáo của CHÍNH người dùng và lấy các mục LỖI. null nếu không tồn tại hoặc không thuộc về họ. */
export async function loadHelpSource(db: D1Like, userId: string, kind: HelpKind, id: string): Promise<HelpSource | null> {
  let label: string, items: ProjectItem[];
  if (kind === "website") {
    const scan = await repo.getScan(db, userId, id);
    if (!scan || scan.status !== "completed") return null;
    label = scan.host;
    items = websiteItems({ scanId: scan.id, host: scan.host, mode: scan.mode, completedAt: scan.completed_at ?? scan.created_at, findings: (await repo.listFindings(db, scan.id)).map(rowToFinding) });
  } else {
    const s = await getProjectScan(db, userId, id);
    if (!s || s.kind !== kind) return null;
    label = s.label; items = s.items;
  }
  return { kind, id, label, items: items.filter((i) => i.status === "fail").sort(bySeverity) };
}

/** Ảnh chụp gửi cho đội kỹ thuật: chỉ tiêu đề, mức độ, vị trí đã che. Không có khoá, token hay nội dung dữ liệu. */
export const toHelpIssue = (i: ProjectItem): HelpIssue => ({ title: i.title, severity: i.severity, group: i.group, source: i.source ?? null, evidence: i.evidence.slice(0, 3) });
