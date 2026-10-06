import { z } from "zod";
import type { NextRequest } from "next/server";
import * as repo from "@/lib/db/repo";
import { getProjectScan, insertProjectScan, latestByLabel } from "@/lib/db/project-repo";
import { UUID, json } from "@/lib/http/guards";
import { rowToFinding } from "@/lib/db-types";
import { projectGuard } from "@/lib/project/api";
import { evaluateLaunch, type ProjectSource, type Skippable, type WebsiteSource } from "@/lib/project/launch";
import type { D1Like } from "@/lib/db/d1";

const id = z.string().regex(UUID).optional();
const Body = z.object({ label: z.string().max(80).optional(), websiteScanId: id, codeId: id, systemId: id, skip: z.array(z.enum(["code", "system"])).max(2).optional(), /** Đánh giá lại dựa trên kết quả MỚI NHẤT của cùng các mục tiêu. */ refreshFrom: id });

async function loadWebsite(db: D1Like, userId: string, scanId?: string): Promise<WebsiteSource | null> {
  if (!scanId) return null;
  const scan = await repo.getScan(db, userId, scanId);
  if (!scan || scan.status !== "completed") return null;
  const findings = (await repo.listFindings(db, scan.id)).map(rowToFinding);
  return { scanId: scan.id, host: scan.host, mode: scan.mode, completedAt: scan.completed_at ?? scan.created_at, findings };
}
const toSource = (r: Awaited<ReturnType<typeof getProjectScan>>): ProjectSource | null => (r ? { id: r.id, label: r.label, createdAt: r.created_at, items: r.items } : null);

/** Tổng hợp kết quả website + mã nguồn + hệ thống đã quét thành một lượt đánh giá sẵn sàng. KHÔNG quét thêm gì: chỉ đọc kết quả của chính người dùng. */
export async function POST(req: NextRequest) {
  const g = await projectGuard(req, { limited: false });
  if (g instanceof Response) return g;
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return json({ error: "invalid_input", message: "Dữ liệu không hợp lệ." }, 400);
  const b = parsed.data;
  const { db, user } = g;

  let { websiteScanId, codeId, systemId } = b;
  let skipped: Skippable[] = b.skip ?? [];
  let label = b.label?.trim() || "";
  let previousId: string | null = null;

  if (b.refreshFrom) {
    // Lấy lượt mới nhất của đúng các mục tiêu đã dùng ở lần trước.
    const prev = await getProjectScan(db, user.id, b.refreshFrom);
    if (!prev || prev.kind !== "launch") return json({ error: "not_found", message: "Không tìm thấy lượt đánh giá trước." }, 404);
    const m = prev.meta as { websiteHost?: string; codeLabel?: string; systemLabel?: string; skipped?: Skippable[] };
    label = prev.label; skipped = m.skipped ?? []; previousId = prev.id;
    if (m.websiteHost) {
      const { results } = await db.prepare("SELECT id FROM scans WHERE user_id = ? AND host = ? AND status = 'completed' ORDER BY completed_at DESC LIMIT 1").bind(user.id, m.websiteHost).all<{ id: string }>();
      websiteScanId = results[0]?.id;
    }
    codeId = m.codeLabel ? (await latestByLabel(db, user.id, "code", m.codeLabel))?.id : undefined;
    systemId = m.systemLabel ? (await latestByLabel(db, user.id, "system", m.systemLabel))?.id : undefined;
  }

  const website = await loadWebsite(db, user.id, websiteScanId);
  const code = codeId ? toSource(await getProjectScan(db, user.id, codeId).then((r) => (r?.kind === "code" ? r : null))) : null;
  const system = systemId ? toSource(await getProjectScan(db, user.id, systemId).then((r) => (r?.kind === "system" ? r : null))) : null;
  if (!website && !code && !system) return json({ error: "no_sources", message: "Hãy chọn ít nhất một kết quả quét để đánh giá." }, 400);

  const ev = evaluateLaunch({ website, code, system, skipped });
  label = label || website?.host || code?.label || system?.label || "Dự án";
  if (!previousId) previousId = (await latestByLabel(db, user.id, "launch", label))?.id ?? null;
  const out = await insertProjectScan(db, {
    userId: user.id, kind: "launch", label, score: ev.score.score, grade: ev.score.grade, verdict: ev.verdict, counts: ev.score.counts, items: ev.items, retentionDays: user.retention_days,
    meta: { websiteScanId: website?.scanId ?? null, websiteHost: website?.host ?? null, websiteAt: website?.completedAt ?? null, codeId: code?.id ?? null, codeLabel: code?.label ?? null, codeAt: code?.createdAt ?? null, systemId: system?.id ?? null, systemLabel: system?.label ?? null, systemAt: system?.createdAt ?? null, skipped, previousId, blockers: ev.blockers.length, shoulds: ev.shoulds.length, reasons: ev.reasons },
  });
  return json({ id: out }, 201);
}
