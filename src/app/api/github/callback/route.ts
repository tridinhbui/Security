import { NextResponse, type NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { env } from "@/lib/env";
import { finishConnect, sealToken, STATE_COOKIE, TOKEN_COOKIE, TOKEN_TTL_S } from "@/lib/github/oauth";

export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin, q = req.nextUrl.searchParams;
  if (!(await getUser())) return NextResponse.redirect(new URL("/login?next=/quet-ma-nguon", origin), 302);
  const token = q.get("error") ? null : await finishConnect({ code: q.get("code"), state: q.get("state"), cookie: req.cookies.get(STATE_COOKIE)?.value, requestOrigin: origin });
  const res = NextResponse.redirect(new URL(`/quet-ma-nguon?github=${token ? "connected" : "failed"}`, origin), 302);
  res.cookies.delete({ name: STATE_COOKIE, path: "/api/github" });
  if (token) res.cookies.set(TOKEN_COOKIE, await sealToken(token), { httpOnly: true, secure: env.isProd, sameSite: "lax", path: "/", maxAge: TOKEN_TTL_S });
  res.headers.set("Cache-Control", "no-store");
  return res;
}
