import { z } from "zod";
import type { NextRequest } from "next/server";
import { insertProjectScan } from "@/lib/db/project-repo";
import { json } from "@/lib/http/guards";
import { log } from "@/lib/log";
import { RepoError } from "@/lib/project/github";
import { projectGuard } from "@/lib/project/api";
import { runCodeScan } from "@/lib/project/code-scan";
import { openToken, TOKEN_COOKIE } from "@/lib/github/oauth";
import { scoreItems } from "@/lib/project/types";

const Body = z.object({ repo: z.string().min(3).max(300), token: z.string().max(300).optional(), useConnected: z.boolean().optional() });
const STATUS: Record<RepoError["code"], number> = { invalid_repo: 400, invalid_token: 400, not_found: 404, auth: 403, rate_limit: 429, too_big: 413, network: 502, empty: 422 };

/** Quét mã nguồn GitHub (chỉ đọc). Token nếu có chỉ dùng trong request này, không được lưu và không được ghi log. */
export async function POST(req: NextRequest) {
  const g = await projectGuard(req, { limited: true });
  if (g instanceof Response) return g;
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return json({ error: "invalid_repo", message: "Hãy nhập kho GitHub dạng owner/repo." }, 400);
  try {
    const token = parsed.data.useConnected ? await openToken(req.cookies.get(TOKEN_COOKIE)?.value) : parsed.data.token;
    if (parsed.data.useConnected && !token) return json({ error: "not_connected", message: "Phiên kết nối GitHub đã hết hạn. Hãy kết nối lại." }, 401);
    const r = await runCodeScan({ repo: parsed.data.repo, token });
    const s = scoreItems(r.items);
    const id = await insertProjectScan(g.db, { userId: g.user.id, kind: "code", label: r.label, stack: "github", score: s.score, grade: s.grade, counts: s.counts, items: r.items, meta: r.meta, retentionDays: g.user.retention_days });
    return json({ id }, 201);
  } catch (e) {
    if (e instanceof RepoError) return json({ error: e.code, message: e.message }, STATUS[e.code]);
    log("error", "code_scan_error", { name: (e as Error).name });
    return json({ error: "internal_error", message: "Đã xảy ra lỗi khi quét mã nguồn. Vui lòng thử lại." }, 500);
  }
}
