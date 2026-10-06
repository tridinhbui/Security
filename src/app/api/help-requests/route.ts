import { z } from "zod";
import type { NextRequest } from "next/server";
import { countRecentHelp, createHelpRequest, HELP_NOTE_MAX } from "@/lib/db/help-repo";
import { bindings } from "@/lib/cf";
import { getUser } from "@/lib/auth/next";
import { json, sameOrigin, UUID } from "@/lib/http/guards";
import { loadHelpSource, toHelpIssue } from "@/lib/project/help";
import { recordEvent } from "@/lib/db/repo";

const Body = z.object({
  kind: z.enum(["website", "code", "system", "launch"]), id: z.string().regex(UUID),
  fingerprints: z.array(z.string().max(300)).max(60).optional(), note: z.string().max(HELP_NOTE_MAX).default(""), contact: z.string().max(120).default(""),
  consent: z.literal(true),
});

/** Gửi yêu cầu nhờ chuyên gia xử lý các lỗi đã chọn. Chỉ chủ báo cáo gửi được. */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden", message: "Yêu cầu từ nguồn khác đã bị từ chối." }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated", message: "Hãy đăng nhập." }, 401);
  const p = Body.safeParse(await req.json().catch(() => null));
  if (!p.success) return json({ error: "invalid_input", message: "Hãy chọn lỗi cần xử lý và đồng ý chia sẻ báo cáo với chuyên gia." }, 400);
  const { DB } = await bindings();
  if ((await countRecentHelp(DB, user.id, 86_400_000)) >= 5) return json({ error: "limit", message: "Bạn đã gửi nhiều yêu cầu trong 24 giờ qua. Đội kỹ thuật sẽ phản hồi sớm." }, 429);
  const src = await loadHelpSource(DB, user.id, p.data.kind, p.data.id);
  if (!src) return json({ error: "not_found", message: "Không tìm thấy báo cáo." }, 404);
  const chosen = p.data.fingerprints?.length ? src.items.filter((i) => p.data.fingerprints!.includes(i.fingerprint)) : src.items;
  if (!chosen.length) return json({ error: "no_issues", message: "Không có lỗi nào để gửi." }, 400);
  const id = await createHelpRequest(DB, { userId: user.id, kind: src.kind, sourceId: src.id, label: src.label, issues: chosen.slice(0, 40).map(toHelpIssue), note: p.data.note.trim(), contact: p.data.contact.trim() || user.email });
  await recordEvent(DB, { type: "help_requested", userId: user.id, meta: { kind: src.kind, issues: chosen.length } }).catch(() => undefined);
  return json({ id }, 201);
}
