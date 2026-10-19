import { getDb } from "@/lib/cf";
import { json } from "@/lib/http/guards";
import { publicStats } from "@/lib/db/stats-repo";

export const dynamic = "force-dynamic";

/** Số lượt quét và số tài khoản (số thật, chỉ là tổng). Cache 30 giây ở trình duyệt/CDN để trang chủ có thể làm mới thường xuyên mà không tốn truy vấn. */
export async function GET() {
  const s = await publicStats(await getDb());
  return json(s, 200, { "Cache-Control": "public, max-age=30, s-maxage=30" });
}
