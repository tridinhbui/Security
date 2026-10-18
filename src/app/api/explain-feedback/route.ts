import type { NextRequest } from "next/server";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { hashIp, hashKey } from "@/lib/crypto";
import { cleanComment, cleanVariant, saveVote } from "@/lib/db/explain-feedback";
import { clientIp, json, sameOrigin, voterNet } from "@/lib/http/guards";
import { ALL_RULES } from "@/lib/scanner/rules";

export const dynamic = "force-dynamic";
const RULE_IDS = new Set(ALL_RULES.map((r) => r.id));

/**
 * Nhận phiếu "Giải thích này có rõ không?". Không cần đăng nhập (dùng được ở quét miễn phí).
 * Chặt chẽ: chỉ mã luật có thật, khoá biến thể đã lọc, không lưu tên miền/URL/IP thô; giới hạn 60 phiếu/giờ/người.
 */
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return json({ error: "forbidden" }, 403);
  if (Number(req.headers.get("content-length") ?? 0) > 4096) return json({ error: "too_large", message: "Dữ liệu quá lớn." }, 413);
  // content-length có thể vắng (chunked) hoặc nói dối: đo độ dài thật của nội dung đã đọc.
  const raw = await req.text().catch(() => "");
  if (raw.length > 4096) return json({ error: "too_large", message: "Dữ liệu quá lớn." }, 413);
  let b: Record<string, unknown> | null = null;
  try { const j = JSON.parse(raw); b = j && typeof j === "object" && !Array.isArray(j) ? (j as Record<string, unknown>) : null; } catch { b = null; }
  const ruleId = String(b?.ruleId ?? "");
  const verdict = b?.verdict === "clear" || b?.verdict === "unclear" ? b.verdict : null;
  const source = b?.source === "full" ? "full" : b?.source === "quick" ? "quick" : null;
  if (!RULE_IDS.has(ruleId) || !verdict || !source) return json({ error: "invalid", message: "Dữ liệu không hợp lệ." }, 400);

  const user = await getUser();
  const ip = clientIp(req);
  const voter = user ? await hashKey("explain-voter", user.id) : await hashIp(voterNet(ip));
  const ok = await saveVote(await getDb(), {
    voter, ruleId, variant: cleanVariant(b?.variant), verdict, source, mode: b?.mode === "technical" ? "technical" : "beginner", comment: cleanComment(b?.comment),
  });
  return ok ? json({ ok: true }, 201) : json({ error: "rate_limited", message: "Bạn đánh giá quá nhanh. Vui lòng thử lại sau." }, 429);
}
