import type { NextRequest } from "next/server";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { hasCronSecret, json } from "@/lib/http/guards";

export const dynamic = "force-dynamic";

/** Operational metrics: queue depth, error rate, worker latency. Contains no scan content. Bearer CRON_SECRET. */
export async function GET(req: NextRequest) {
  if (!hasCronSecret(req)) return json({ error: "unauthorized" }, 401);
  return json(await repo.metrics(await getDb()));
}
