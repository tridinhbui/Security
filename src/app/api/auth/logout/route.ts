import { NextResponse, type NextRequest } from "next/server";
import { logout } from "@/lib/auth/core";
import { SESSION_COOKIE } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { json, sameOrigin } from "@/lib/http/guards";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  await logout(await getDb(), req.cookies.get(SESSION_COOKIE)?.value);
  const res = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  res.cookies.delete(SESSION_COOKIE);
  return res;
}
