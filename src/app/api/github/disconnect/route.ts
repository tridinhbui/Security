import { NextResponse, type NextRequest } from "next/server";
import { json, sameOrigin } from "@/lib/http/guards";
import { TOKEN_COOKIE } from "@/lib/github/oauth";

export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  const res = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  res.cookies.delete({ name: TOKEN_COOKIE, path: "/" });
  return res;
}
