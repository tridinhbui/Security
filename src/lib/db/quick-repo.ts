import { isoAgo, nowIso, parseJson, type D1Like } from "./d1";

const HOUR = 3_600_000, DAY = 86_400_000;
export const QUICK_CACHE_TTL_MS = 6 * HOUR;

export async function getQuickCache<T>(db: D1Like, host: string, engineVersion: number): Promise<T | null> {
  const r = await db.prepare("SELECT payload FROM quick_scan_cache WHERE host = ? AND engine_version = ? AND created_at > ?").bind(host, engineVersion, isoAgo(QUICK_CACHE_TTL_MS)).first<{ payload: string }>();
  return r ? parseJson<T | null>(r.payload, null) : null;
}
export const putQuickCache = (db: D1Like, host: string, engineVersion: number, payload: unknown) =>
  db.prepare("INSERT INTO quick_scan_cache (host,engine_version,payload,created_at) VALUES (?,?,?,?) ON CONFLICT(host) DO UPDATE SET engine_version=excluded.engine_version, payload=excluded.payload, created_at=excluded.created_at")
    .bind(host, engineVersion, JSON.stringify(payload), nowIso()).run();

export const logQuickScan = (db: D1Like, ipHash: string, host: string, cached: boolean) =>
  db.prepare("INSERT INTO quick_scan_log (ip_hash,host,cached,at) VALUES (?,?,?,?)").bind(ipHash, host, cached ? 1 : 0, nowIso()).run();

async function count(db: D1Like, sql: string, ...p: (string | number)[]) {
  return (await db.prepare(sql).bind(...p).first<{ c: number }>())?.c ?? 0;
}
/** Số lượt quét THẬT (không tính lượt trúng bộ nhớ đệm) của một IP trong khoảng thời gian. */
export const freshByIp = (db: D1Like, ipHash: string, windowMs: number) => count(db, "SELECT COUNT(*) c FROM quick_scan_log WHERE ip_hash = ? AND cached = 0 AND at > ?", ipHash, isoAgo(windowMs));
/** Mọi lượt (kể cả trúng đệm) của một IP: chặn việc gọi dồn dập. */
export const anyByIp = (db: D1Like, ipHash: string, windowMs: number) => count(db, "SELECT COUNT(*) c FROM quick_scan_log WHERE ip_hash = ? AND at > ?", ipHash, isoAgo(windowMs));
export const freshGlobal = (db: D1Like, windowMs: number) => count(db, "SELECT COUNT(*) c FROM quick_scan_log WHERE cached = 0 AND at > ?", isoAgo(windowMs));
/** Số lượt quét thật tới cùng một tên miền (bảo vệ website bị quét). */
export const freshByHost = (db: D1Like, host: string, windowMs: number) => count(db, "SELECT COUNT(*) c FROM quick_scan_log WHERE host = ? AND cached = 0 AND at > ?", host, isoAgo(windowMs));

export type QuickLimitHit = "ip" | "host" | "global";
/**
 * GIỮ CHỖ một lượt quét thật rồi mới đếm, để các yêu cầu ĐỒNG THỜI không cùng lọt qua hạn mức (trước đây: đếm rồi mới ghi, nên 8 yêu cầu
 * song song tới cùng một website đều được quét dù hạn mức là 3/giờ). Chỉ đếm các dòng có id ≤ id của mình: N yêu cầu đầu tiên được quét,
 * phần còn lại bị từ chối và xoá chỗ đã giữ. Không bao giờ vượt hạn mức; trong trường hợp xấu nhất từ chối hơi nhiều hơn cần thiết.
 */
export async function reserveFreshQuickScan(db: D1Like, ipHash: string, host: string, l: { freshPerHour: number; freshPerDay: number; hostPerHour: number; globalPerDay: number }): Promise<{ ok: true; id: number } | { ok: false; hit: QuickLimitHit }> {
  const row = await db.prepare("INSERT INTO quick_scan_log (ip_hash,host,cached,at) VALUES (?,?,0,?) RETURNING id").bind(ipHash, host, nowIso()).first<{ id: number }>();
  const id = row!.id;
  const upTo = (sql: string, ...p: (string | number)[]) => count(db, `${sql} AND id <= ?`, ...p, id);
  const hit: QuickLimitHit | null =
    (await upTo("SELECT COUNT(*) c FROM quick_scan_log WHERE ip_hash = ? AND cached = 0 AND at > ?", ipHash, isoAgo(HOUR))) > l.freshPerHour ||
    (await upTo("SELECT COUNT(*) c FROM quick_scan_log WHERE ip_hash = ? AND cached = 0 AND at > ?", ipHash, isoAgo(DAY))) > l.freshPerDay ? "ip"
    : (await upTo("SELECT COUNT(*) c FROM quick_scan_log WHERE host = ? AND cached = 0 AND at > ?", host, isoAgo(HOUR))) > l.hostPerHour ? "host"
    : (await upTo("SELECT COUNT(*) c FROM quick_scan_log WHERE cached = 0 AND at > ?", isoAgo(DAY))) > l.globalPerDay ? "global"
    : null;
  if (hit) { await db.prepare("DELETE FROM quick_scan_log WHERE id = ?").bind(id).run(); return { ok: false, hit }; }
  return { ok: true, id };
}

/** Dọn dữ liệu cũ (gọi cơ hội mỗi lần quét thật; rẻ nhờ chỉ mục theo thời gian). */
export async function purgeQuick(db: D1Like) {
  await db.batch([
    db.prepare("DELETE FROM quick_scan_log WHERE at < ?").bind(isoAgo(2 * DAY)),
    db.prepare("DELETE FROM quick_scan_cache WHERE created_at < ?").bind(isoAgo(2 * DAY)),
  ]);
}
export { HOUR, DAY };
