import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/auth/next";
import { GoogleAuthError } from "@/lib/auth/google";
import { finishGoogleLogin, OAUTH_COOKIE } from "@/lib/auth/google-flow";
import { getDb } from "@/lib/cf";
import { hashIp } from "@/lib/crypto";
import { clientIp } from "@/lib/http/guards";

/** Google chuyển người dùng về đây. Mọi lỗi đều trở về /login với mã an toàn, không lộ chi tiết nội bộ. */
export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin;
  const q = req.nextUrl.searchParams;
  const ip = clientIp(req);
  try {
    const r = await finishGoogleLogin(
      { code: q.get("code"), state: q.get("state"), error: q.get("error"), cookie: req.cookies.get(OAUTH_COOKIE)?.value, requestOrigin: origin, ipHash: ip ? await hashIp(ip) : null },
      { db: await getDb() },
    );
    const res = NextResponse.redirect(new URL(r.next, origin), { status: 302 });
    res.cookies.set(SESSION_COOKIE, r.token, sessionCookieOptions(r.expiresAt));
    res.cookies.delete({ name: OAUTH_COOKIE, path: "/api/auth/google" });
    res.headers.set("Cache-Control", "no-store");
    return res;
  } catch (e) {
    const code = e instanceof GoogleAuthError ? e.code : "token_exchange";
    const res = NextResponse.redirect(new URL(`/login?error=${code}`, origin), { status: 302 });
    res.cookies.delete({ name: OAUTH_COOKIE, path: "/api/auth/google" });
    return res;
  }
}
