import type { NextRequest } from "next/server";
import { z } from "zod";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { json, sameOrigin } from "@/lib/http/guards";

const Body = z.object({ retention_days: z.union([z.literal(7), z.literal(30), z.literal(90), z.literal(365)]) });

/** Update data-retention. Existing reports are re-dated in the same transaction. */
export async function PATCH(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return json({ error: "invalid", message: "Choose 7, 30, 90 or 365 days." }, 400);
  await repo.setRetention(await getDb(), user.id, parsed.data.retention_days);
  return json({ ok: true });
}
