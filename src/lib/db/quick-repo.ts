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

/** Dọn dữ liệu cũ (gọi cơ hội mỗi lần quét thật; rẻ nhờ chỉ mục theo thời gian). */
export async function purgeQuick(db: D1Like) {
  await db.batch([
    db.prepare("DELETE FROM quick_scan_log WHERE at < ?").bind(isoAgo(2 * DAY)),
    db.prepare("DELETE FROM quick_scan_cache WHERE created_at < ?").bind(isoAgo(2 * DAY)),
  ]);
}
export { HOUR, DAY };
