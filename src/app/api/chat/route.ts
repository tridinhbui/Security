import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { isoAgo } from "@/lib/db/d1";
import { json, sameOrigin } from "@/lib/http/guards";

export const dynamic = "force-dynamic";

/** Người dùng xem luồng chat của chính mình (và đánh dấu tin của quản trị viên là đã đọc). */
export async function GET() {
  const user = await getUser();
  if (!user) return json({ error: "unauthorized" }, 401);
  const db = await getDb();
  await repo.markChatRead(db, user.id, "user");
  return json({ messages: await repo.listChat(db, user.id) });
}

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthorized" }, 401);
  const body = String(((await req.json().catch(() => null)) as { body?: unknown } | null)?.body ?? "").trim();
  if (!body) return json({ error: "empty", message: "Tin nhắn trống." }, 400);
  if (body.length > repo.CHAT_MAX_LEN) return json({ error: "too_long", message: `Tin nhắn tối đa ${repo.CHAT_MAX_LEN} ký tự.` }, 400);
  const db = await getDb();
  if ((await repo.countChatSince(db, user.id, "user", isoAgo(3_600_000))) >= 30) return json({ error: "rate_limited", message: "Bạn gửi quá nhiều tin nhắn. Vui lòng thử lại sau." }, 429);
  return json({ message: await repo.sendChat(db, user.id, "user", body) }, 201);
}
