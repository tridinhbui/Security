import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

type Ctx = { params: Promise<{ id: string }> };

/** Status poll. The repo only returns scans owned by the signed-in user. */
export async function GET(_req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  if (!UUID.test(id)) return json({ error: "not_found" }, 404);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const s = await repo.getScan(await getDb(), user.id, id);
  if (!s) return json({ error: "not_found" }, 404);
  return json({ id: s.id, status: s.status, score: s.score, grade: s.grade, error_code: s.error_code, error_message: s.error_message, created_at: s.created_at, completed_at: s.completed_at });
}

export async function DELETE(req: NextRequest, { params }: Ctx) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const { id } = await params;
  if (!UUID.test(id)) return json({ error: "not_found" }, 404);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const db = await getDb();
  if (!(await repo.deleteScan(db, user.id, id))) return json({ error: "not_found" }, 404);
  await repo.recordEvent(db, { type: "scan_deleted", userId: user.id, meta: { scan: id } });
  return json({ ok: true });
}
