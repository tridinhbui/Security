import { NextResponse, type NextRequest } from "next/server";
import { startGoogleLogin, OAUTH_COOKIE, OAUTH_TTL_MS } from "@/lib/auth/google-flow";
import { GoogleAuthError } from "@/lib/auth/google";
import { env } from "@/lib/env";

/** Bắt đầu đăng nhập Google: tạo state/nonce/PKCE, lưu trong cookie mã hoá, chuyển hướng tới Google. */
export async function GET(req: NextRequest) {
  const origin = req.nextUrl.origin;
  try {
    const { location, cookie } = await startGoogleLogin({ next: req.nextUrl.searchParams.get("next"), requestOrigin: origin });
    const res = NextResponse.redirect(location, { status: 302 });
    res.cookies.set(OAUTH_COOKIE, cookie, { httpOnly: true, secure: env.isProd, sameSite: "lax", path: "/api/auth/google", maxAge: OAUTH_TTL_MS / 1000 });
    res.headers.set("Cache-Control", "no-store");
    return res;
  } catch (e) {
    const code = e instanceof GoogleAuthError ? e.code : "token_exchange";
    return NextResponse.redirect(new URL(`/login?error=${code}`, origin), { status: 302 });
  }
}
