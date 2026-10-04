import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { login } from "@/lib/auth/core";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth/next";
import { verifyTurnstile } from "@/lib/auth/turnstile";
import { getDb } from "@/lib/cf";
import { hashIp } from "@/lib/crypto";
import { env } from "@/lib/env";
import { clientIp, json, sameOrigin } from "@/lib/http/guards";

const Body = z.object({ email: z.string().max(320), password: z.string().max(256), turnstile: z.string().max(4096).optional() });

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden", message: "Cross-origin request rejected." }, 403);
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return json({ error: "invalid", message: "Enter your email and password." }, 400);
  const ip = clientIp(req);
  if (!(await verifyTurnstile(env.turnstileSecret, parsed.data.turnstile, ip))) return json({ error: "captcha", message: "Please complete the verification challenge." }, 400);

  const r = await login(await getDb(), { email: parsed.data.email, password: parsed.data.password, ipHash: ip ? await hashIp(ip) : null });
  if (!r.ok) return json({ error: r.error, message: r.message }, r.status);
  const res = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  res.cookies.set(SESSION_COOKIE, r.token, sessionCookieOptions(r.expiresAt));
  return res;
}
