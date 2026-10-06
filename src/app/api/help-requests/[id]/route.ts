import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { bindings } from "@/lib/cf";
import { cancelMyHelp } from "@/lib/db/help-repo";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

/** Người dùng huỷ yêu cầu của chính mình (khi chưa bắt đầu xử lý). */
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  if (!UUID.test(id)) return json({ error: "bad_request" }, 400);
  const { DB } = await bindings();
  return (await cancelMyHelp(DB, user.id, id)) ? json({ ok: true }) : json({ error: "not_found", message: "Không thể huỷ yêu cầu này." }, 404);
}
