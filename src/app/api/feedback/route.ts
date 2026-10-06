import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

export const dynamic = "force-dynamic";

/** Nhận phản hồi sau khi quét xong. Chỉ chủ lượt quét được gửi; dữ liệu được kiểm tra chặt phía máy chủ. */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthorized" }, 401);
  const b = (await req.json().catch(() => null)) as { scanId?: unknown; rating?: unknown; tags?: unknown; comment?: unknown } | null;
  const scanId = String(b?.scanId ?? "");
  const rating = Number(b?.rating);
  if (!UUID.test(scanId) || !Number.isInteger(rating) || rating < 1 || rating > 5) return json({ error: "invalid", message: "Dữ liệu không hợp lệ." }, 400);
  const tags = Array.isArray(b?.tags) ? b.tags.filter((x): x is string => typeof x === "string").slice(0, 6) : [];
  const comment = String(b?.comment ?? "").trim();
  const ok = await repo.saveFeedback(await getDb(), user.id, scanId, rating, tags, comment);
  return ok ? json({ ok: true }, 201) : json({ error: "not_found" }, 404);
}
