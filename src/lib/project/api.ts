import type { NextRequest } from "next/server";
import { getUser, type SessionUser } from "../auth/next";
import { bindings } from "../cf";
import * as repo from "../db/repo";
import type { D1Like } from "../db/d1";
import { json, sameOrigin } from "../http/guards";

const HOUR = 3_600_000;
export const PROJECT_SCANS_PER_HOUR = 8;

/** Kiểm tra chung cho API quét dự án: cùng nguồn gốc (CSRF), đã đăng nhập, và (tuỳ chọn) hạn mức theo giờ. */
export async function projectGuard(req: NextRequest, opts: { limited: boolean }): Promise<{ user: SessionUser; db: D1Like } | Response> {
  if (!sameOrigin(req)) return json({ error: "forbidden", message: "Yêu cầu từ nguồn khác đã bị từ chối." }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated", message: "Hãy đăng nhập để sử dụng." }, 401);
  const { DB } = await bindings();
  if (opts.limited) {
    if ((await repo.countAttempts(DB, "project_scan", user.id, HOUR)) >= PROJECT_SCANS_PER_HOUR) return json({ error: "hourly_limit", message: "Bạn đã quét khá nhiều trong một giờ qua. Vui lòng thử lại sau." }, 429, { "Retry-After": "3600" });
    await repo.recordAttempt(DB, "project_scan", user.id);
  }
  return { user, db: DB };
}
