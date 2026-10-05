import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { getUser } from "@/lib/auth/next";
import { bindings } from "@/lib/cf";
import { hashIp } from "@/lib/crypto";
import * as repo from "@/lib/db/repo";
import { clientIp, json, sameOrigin } from "@/lib/http/guards";
import { createScan } from "@/lib/jobs/create-scan";
import { log } from "@/lib/log";
import { createDohResolver } from "@/lib/ssrf/doh";

const Body = z.object({ url: z.string().min(1).max(2048), quick: z.boolean().optional() });

/** Create a scan and enqueue it. Returns immediately with the scan id; the queue consumer + container do the rest. */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden", message: "Yêu cầu từ nguồn khác đã bị từ chối." }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated", message: "Hãy đăng nhập để quét website." }, 401);
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return json({ error: "invalid_url", message: "Hãy nhập địa chỉ website." }, 400);

  const { DB, SCAN_QUEUE } = await bindings();
  const ip = clientIp(req);
  const result = await createScan(DB, user.id, parsed.data.url, ip ? await hashIp(ip) : null, createDohResolver(), { quick: parsed.data.quick });
  if (!result.ok) return json({ error: result.code, message: result.message }, result.status, result.retryAfter ? { "Retry-After": "3600" } : undefined);

  if (result.cached) return NextResponse.json({ id: result.id, cached: true }, { status: 201, headers: { "Cache-Control": "no-store" } });
  try {
    await SCAN_QUEUE.send({ scanId: result.id });
  } catch {
    log("error", "queue_send_failed", { scan: result.id }); // the cron sweep re-sends scans stuck in 'queued'
  }
  return NextResponse.json({ id: result.id }, { status: 202, headers: { "Cache-Control": "no-store" } });
}

/** Delete ALL of the signed-in user's reports. */
export async function DELETE(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const user = await getUser();
  if (!user) return json({ error: "unauthenticated" }, 401);
  const { DB } = await bindings();
  const n = await repo.deleteAllScans(DB, user.id);
  await repo.recordEvent(DB, { type: "scan_deleted", userId: user.id, message: "all", meta: { count: n } });
  return json({ ok: true, deleted: n });
}
