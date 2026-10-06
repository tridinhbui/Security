import { z } from "zod";
import type { NextRequest } from "next/server";
import { insertProjectScan } from "@/lib/db/project-repo";
import { json } from "@/lib/http/guards";
import { log } from "@/lib/log";
import { projectGuard } from "@/lib/project/api";
import { scanFirebase, scanSupabase, SystemScanError } from "@/lib/project/system-scan";
import { createDohResolver } from "@/lib/ssrf/doh";
import { recordSsrfStrike } from "@/lib/jobs/abuse";
import { env } from "@/lib/env";
import { DiscoverError, discoverBackend } from "@/lib/project/discover";
import { scoreItems } from "@/lib/project/types";

const list = z.array(z.string().max(64)).max(40).optional();
const Body = z.discriminatedUnion("stack", [
  z.object({ stack: z.literal("auto"), consent: z.literal(true), siteUrl: z.string().min(3).max(2048) }),
  z.object({ stack: z.literal("supabase"), consent: z.literal(true), url: z.string().min(5).max(200), anonKey: z.string().min(10).max(2000), tables: list, buckets: list }),
  z.object({ stack: z.literal("firebase"), consent: z.literal(true), projectId: z.string().min(5).max(60), apiKey: z.string().max(100).optional(), databaseURL: z.string().max(200).optional(), storageBucket: z.string().max(100).optional() }),
]);

/** Quét hệ thống (Supabase / Firebase), thụ động: chỉ dùng khoá công khai, không ghi/sửa/xoá. Khoá không được lưu hay ghi log. */
export async function POST(req: NextRequest) {
  const body = Body.safeParse(await req.json().catch(() => null));
  if (!body.success) return json({ error: "invalid_input", message: "Hãy điền đủ thông tin và xác nhận bạn có quyền kiểm tra dự án này." }, 400);
  const g = await projectGuard(req, { limited: true });
  if (g instanceof Response) return g;
  try {
    const d = body.data;
    if (d.stack === "auto") {
      const found = await discoverBackend(d.siteUrl, { resolver: createDohResolver(), denyHosts: [new URL(env.siteUrl).hostname] });
      const parts = await Promise.all([
        found.supabase ? scanSupabase(found.supabase).then((r) => ({ stack: "supabase", ...r })) : null,
        found.firebase ? scanFirebase(found.firebase).then((r) => ({ stack: "firebase", ...r })) : null,
      ]);
      const hit = parts.filter((p): p is NonNullable<typeof p> => !!p);
      if (!hit.length) return json({ error: "not_detected", message: `Không thấy cấu hình Supabase hoặc Firebase trong website ${found.host}. Có thể bạn dùng nền tảng khác, hoặc cấu hình nằm ở nơi chúng tôi không đọc được. Hãy chọn "Nhập thủ công".` }, 422);
      const items = hit.flatMap((p) => p.items);
      const s = scoreItems(items);
      const stack = hit.map((p) => p.stack).join("+");
      const id = await insertProjectScan(g.db, { userId: g.user.id, kind: "system", label: found.host, stack, score: s.score, grade: s.grade, counts: s.counts, items, meta: { stack, site: found.host, detected: hit.map((p) => ({ stack: p.stack, project: p.label })) }, retentionDays: g.user.retention_days });
      return json({ id }, 201);
    }
    const r = d.stack === "supabase"
      ? await scanSupabase({ url: d.url, anonKey: d.anonKey, tables: d.tables, buckets: d.buckets })
      : await scanFirebase({ projectId: d.projectId, apiKey: d.apiKey, databaseURL: d.databaseURL, storageBucket: d.storageBucket });
    const s = scoreItems(r.items);
    const id = await insertProjectScan(g.db, { userId: g.user.id, kind: "system", label: r.label, stack: d.stack, score: s.score, grade: s.grade, counts: s.counts, items: r.items, meta: { stack: d.stack }, retentionDays: g.user.retention_days });
    return json({ id }, 201);
  } catch (e) {
    if (e instanceof DiscoverError) {
      if (e.blocked) await recordSsrfStrike(g.db, g.user.id, { code: e.code, stage: "input", host: body.data.stack === "auto" ? body.data.siteUrl.slice(0, 120) : undefined });
      return json({ error: e.code, message: e.message }, 400);
    }
    if (e instanceof SystemScanError) return json({ error: e.code, message: e.message }, 400);
    log("error", "system_scan_error", { name: (e as Error).name });
    return json({ error: "internal_error", message: "Đã xảy ra lỗi khi quét hệ thống. Vui lòng thử lại." }, 500);
  }
}
