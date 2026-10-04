import { NextResponse, type NextRequest } from "next/server";
import { safeEqual } from "../crypto";
import { env } from "../env";

export const json = (body: unknown, status = 200, headers?: Record<string, string>) =>
  NextResponse.json(body, { status, headers: { "Cache-Control": "no-store", ...headers } });

/** CSRF defence for cookie-authenticated JSON endpoints: require a same-origin Origin header. */
export function sameOrigin(req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).host === (req.headers.get("x-forwarded-host") ?? req.headers.get("host"));
  } catch {
    return false;
  }
}

/** On Cloudflare, `cf-connecting-ip` is set by the edge (client-supplied values are overwritten), so it is trustworthy. */
export function clientIp(req: NextRequest): string | null {
  const xff = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip") ?? xff ?? null;
}

/** Bearer-token check for ops endpoints (metrics). Constant-time. */
export function hasCronSecret(req: NextRequest): boolean {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  try {
    return token.length > 0 && safeEqual(token, env.cronSecret);
  } catch {
    return false;
  }
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
