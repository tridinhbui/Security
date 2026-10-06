import type { NextRequest } from "next/server";
import { bindings } from "@/lib/cf";
import { hashIp } from "@/lib/crypto";
import { clientIp, json, sameOrigin } from "@/lib/http/guards";
import { quickScan } from "@/lib/jobs/quick-scan";
import { log } from "@/lib/log";
import { createDohResolver } from "@/lib/ssrf/doh";
import { env } from "@/lib/env";

export const dynamic = "force-dynamic";

/** Quét nhanh miễn phí, không cần tài khoản. Chạy thật trong Worker (không container, không hàng đợi). */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden", message: "Yêu cầu từ nguồn khác đã bị từ chối." }, 403);
  const body = (await req.json().catch(() => null)) as { url?: unknown } | null;
  if (typeof body?.url !== "string") return json({ error: "invalid_url", message: "Hãy nhập địa chỉ website, ví dụ example.com." }, 400);

  const { DB } = await bindings();
  const ip = clientIp(req);
  const selfHost = (() => { try { return new URL(env.siteUrl).hostname; } catch { return null; } })();
  try {
    const out = await quickScan(DB, { url: body.url, ipHash: await hashIp(ip ?? "unknown"), resolver: createDohResolver(), denyHosts: selfHost ? [selfHost] : [] });
    if (!out.ok) return json({ error: out.code, message: out.message }, out.status, out.status === 429 ? { "Retry-After": "600" } : undefined);
    return json({ ...out.result, cached: out.cached });
  } catch (e) {
    log("error", "quick_scan_failed", { name: (e as Error).name });
    return json({ error: "internal", message: "Không thể quét lúc này. Vui lòng thử lại sau ít phút." }, 500);
  }
}
