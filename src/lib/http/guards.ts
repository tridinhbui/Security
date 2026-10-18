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

/** IPv6: một thuê bao thường được cấp cả /64, nên gom về /64 để việc đổi địa chỉ trong cùng dải không tạo ra "người" mới. */
export function voterNet(ip: string | null): string {
  if (!ip) return "unknown";
  if (!ip.includes(":")) return ip;
  const mapped = /^(?:0{0,4}:){2,5}(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip.split("%")[0]!);
  if (mapped) return mapped[1]!; // IPv4 nhúng trong IPv6 (::ffff:1.2.3.4) là một máy IPv4, KHÔNG được gom chung vào /64 toàn số 0
  const a = ip.split("%")[0]!.toLowerCase().split("::");
  const head = a[0] ? a[0].split(":") : [];
  const tail = a[1] ? a[1].split(":") : [];
  const full = a.length === 2 ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail] : head;
  return full.length === 8 ? `${full.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":")}::/64` : ip;
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
