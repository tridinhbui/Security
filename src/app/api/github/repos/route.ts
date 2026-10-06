import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { json } from "@/lib/http/guards";
import { listRepos, openToken, TOKEN_COOKIE } from "@/lib/github/oauth";

export async function GET(req: NextRequest) {
  if (!(await getUser())) return json({ error: "unauthenticated" }, 401);
  const token = await openToken(req.cookies.get(TOKEN_COOKIE)?.value);
  if (!token) return json({ error: "not_connected", message: "Chưa kết nối GitHub hoặc phiên kết nối đã hết hạn." }, 401);
  const repos = await listRepos(token);
  return repos ? json({ repos }) : json({ error: "github_error", message: "Không lấy được danh sách repo. Hãy kết nối lại GitHub." }, 502);
}
