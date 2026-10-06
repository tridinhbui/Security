import { z } from "zod";
import type { NextRequest } from "next/server";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import { adminUpdateHelp, HELP_QUOTE_MAX } from "@/lib/db/help-repo";
import { json, sameOrigin, UUID } from "@/lib/http/guards";

const Body = z.object({ status: z.enum(["new", "quoted", "in_progress", "done"]), quote: z.string().max(HELP_QUOTE_MAX) });

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  if (!(await getAdmin())) return json({ error: "not_found" }, 404);
  const p = Body.safeParse(await req.json().catch(() => null));
  if (!UUID.test(id) || !p.success) return json({ error: "bad_request" }, 400);
  return (await adminUpdateHelp(await getDb(), id, p.data.status, p.data.quote.trim())) ? json({ ok: true }) : json({ error: "not_found" }, 404);
}
