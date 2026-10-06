import type { D1Like } from "../db/d1";
import * as quick from "../db/quick-repo";
import * as repo from "../db/repo";
import type { Resolver } from "../ssrf/dns";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { runQuickScan, type QuickResult } from "../scanner/quick";
import type { TlsInspection } from "../scanner/tls-inspect";
import { ENGINE_VERSION } from "../scanner/version";

export type QuickOutcome =
  | { ok: true; result: QuickResult; cached: boolean }
  | { ok: false; status: number; code: string; message: string };

export interface QuickLimits { anyPerHour: number; freshPerHour: number; freshPerDay: number; hostPerHour: number; globalPerDay: number }
const num = (k: string, d: number) => { const n = Number(process.env[k]); return Number.isFinite(n) && n > 0 ? n : d; };
export const quickLimits = (): QuickLimits => ({
  anyPerHour: num("QUICK_SCAN_ANY_PER_HOUR", 40), freshPerHour: num("QUICK_SCAN_PER_IP_HOUR", 6), freshPerDay: num("QUICK_SCAN_PER_IP_DAY", 15),
  hostPerHour: num("QUICK_SCAN_PER_HOST_HOUR", 3), globalPerDay: num("QUICK_SCAN_GLOBAL_DAILY", 300),
});

const TOO_MANY = (message: string): QuickOutcome => ({ ok: false, status: 429, code: "rate_limited", message });

/**
 * Quét nhanh không cần tài khoản. Thứ tự bảo vệ: kiểm tra URL/SSRF → giới hạn gọi dồn dập theo IP → bộ nhớ đệm theo tên miền (6 giờ,
 * không tốn tài nguyên) → hạn mức quét thật theo IP / theo tên miền / toàn hệ thống → quét. IP chỉ được lưu dạng băm.
 */
export async function quickScan(db: D1Like, a: { url: string; ipHash: string; resolver: Resolver; fetchImpl?: typeof fetch; denyHosts?: string[]; limits?: QuickLimits }): Promise<QuickOutcome> {
  const L = a.limits ?? quickLimits();
  if (typeof a.url !== "string" || a.url.trim().length === 0 || a.url.length > 2048) return { ok: false, status: 400, code: "invalid_url", message: "Hãy nhập địa chỉ website, ví dụ example.com." };

  let host: string;
  try {
    host = normalizeTargetUrl(a.url).host;
  } catch (e) {
    if (e instanceof SsrfError) {
      await quick.logQuickScan(db, a.ipHash, "invalid", false).catch(() => undefined); // thăm dò mục tiêu nội bộ cũng tính vào hạn mức
      return { ok: false, status: 400, code: e.code, message: e.message };
    }
    throw e;
  }

  if ((await quick.anyByIp(db, a.ipHash, quick.HOUR)) >= L.anyPerHour) return TOO_MANY("Bạn thử quá nhiều lần. Vui lòng quay lại sau ít phút, hoặc đăng nhập để quét không giới hạn trong hạn mức tài khoản.");

  const hit = await quick.getQuickCache<QuickResult>(db, host, ENGINE_VERSION);
  if (hit) { await quick.logQuickScan(db, a.ipHash, host, true).catch(() => undefined); return { ok: true, result: hit, cached: true }; }

  if ((await quick.freshByIp(db, a.ipHash, quick.HOUR)) >= L.freshPerHour || (await quick.freshByIp(db, a.ipHash, quick.DAY)) >= L.freshPerDay)
    return TOO_MANY("Bạn đã dùng hết lượt quét thử miễn phí. Hãy đăng nhập để tiếp tục, hoặc quay lại sau.");
  if ((await quick.freshByHost(db, host, quick.HOUR)) >= L.hostPerHour) return TOO_MANY("Website này vừa được quét nhiều lần. Để tránh gây quá tải cho website, vui lòng chờ một lúc rồi thử lại.");
  if ((await quick.freshGlobal(db, quick.DAY)) >= L.globalPerDay) return TOO_MANY("Quét thử miễn phí đang tạm đạt giới hạn trong ngày. Hãy đăng nhập để quét, hoặc quay lại vào ngày mai.");

  await quick.logQuickScan(db, a.ipHash, host, false); // ghi TRƯỚC khi quét: các yêu cầu đồng thời không lách được hạn mức
  try {
    const result = await runQuickScan(a.url, {
      resolver: a.resolver, fetchImpl: a.fetchImpl, denyHosts: a.denyHosts,
      tlsFor: async (h) => { const c = await repo.getTlsCache<TlsInspection>(db, h); return c && c.ok === true ? c.tls : null; },
    });
    await quick.putQuickCache(db, host, ENGINE_VERSION, result).catch(() => undefined);
    if (crypto.getRandomValues(new Uint8Array(1))[0]! < 13) await quick.purgeQuick(db).catch(() => undefined); // ~5%: dọn dữ liệu cũ
    return { ok: true, result, cached: false };
  } catch (e) {
    if (e instanceof SsrfError) return { ok: false, status: 400, code: e.code, message: e.message };
    throw e;
  }
}
