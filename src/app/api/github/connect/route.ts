import { NextResponse, type NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { env } from "@/lib/env";
import { startConnect, STATE_COOKIE, STATE_TTL_S } from "@/lib/github/oauth";

export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin;
  if (!(await getUser())) return NextResponse.redirect(new URL("/login?next=/quet-ma-nguon", origin), 302);
  const s = await startConnect(origin);
  if (!s) return NextResponse.redirect(new URL("/quet-ma-nguon?github=not_configured", origin), 302);
  const res = NextResponse.redirect(s.location, 302);
  res.cookies.set(STATE_COOKIE, s.cookie, { httpOnly: true, secure: env.isProd, sameSite: "lax", path: "/api/github", maxAge: STATE_TTL_S });
  res.headers.set("Cache-Control", "no-store");
  return res;
}
