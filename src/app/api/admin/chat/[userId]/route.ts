import type { NextRequest } from "next/server";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

export const dynamic = "force-dynamic";
type Ctx = { params: Promise<{ userId: string }> };

// Không phải quản trị viên → 404 (không tiết lộ sự tồn tại của khu vực quản trị).
export async function GET(_req: NextRequest, { params }: Ctx) {
  const { userId } = await params;
  if (!(await getAdmin())) return json({ error: "not_found" }, 404);
  if (!UUID.test(userId)) return json({ error: "bad_request" }, 400);
  const db = await getDb();
  await repo.markChatRead(db, userId, "admin");
  return json({ messages: await repo.listChat(db, userId) });
}

export async function POST(req: NextRequest, { params }: Ctx) {
  const { userId } = await params;
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  if (!(await getAdmin())) return json({ error: "not_found" }, 404);
  if (!UUID.test(userId)) return json({ error: "bad_request" }, 400);
  const body = String(((await req.json().catch(() => null)) as { body?: unknown } | null)?.body ?? "").trim();
  if (!body || body.length > repo.CHAT_MAX_LEN) return json({ error: "bad_request", message: "Tin nhắn trống hoặc quá dài." }, 400);
  const db = await getDb();
  if (!(await repo.adminGetUser(db, userId))) return json({ error: "not_found" }, 404);
  return json({ message: await repo.sendChat(db, userId, "admin", body) }, 201);
}
