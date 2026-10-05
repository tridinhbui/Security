import type { D1Like } from "../db/d1";
import * as repo from "../db/repo";
import { env } from "../env";
import { resolvePublicAddresses, type Resolver } from "../ssrf/dns";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { recordSsrfStrike } from "./abuse";

export type CreateScanResult =
  | { ok: true; id: string; cached?: boolean }
  | { ok: false; status: number; code: string; message: string; retryAfter?: string };

/** Audit logs keep the target but never the query string or fragment, which can carry tokens. */
const stripQuery = (u: string) => u.split(/[?#]/)[0]!.slice(0, 120);

const LIMIT_MESSAGES: Record<string, string> = {
  account_blocked: "Tài khoản của bạn tạm thời bị khoá chức năng quét do nhiều yêu cầu bị chặn liên tiếp.",
  too_many_concurrent: "Bạn đang có lượt quét chạy. Hãy chờ lượt đó hoàn tất trước khi bắt đầu lượt mới.",
  hourly_limit: "Bạn đã đạt giới hạn quét mỗi giờ. Vui lòng thử lại sau.",
  daily_quota: "Bạn đã dùng hết hạn mức quét trong ngày. Hạn mức được tính theo cửa sổ trượt 24 giờ.",
  monthly_quota: "Bạn đã dùng hết hạn mức quét trong 30 ngày gần nhất. Hạn mức được tính theo cửa sổ trượt 30 ngày.",
  global_cap: "Hệ thống đã đạt giới hạn quét trong 24 giờ qua để giữ chi phí ở mức thấp. Vui lòng quay lại sau.",
  ip_limit: "Có quá nhiều lượt quét từ mạng của bạn. Vui lòng thử lại sau.",
  host_limit: "Website này vừa được quét nhiều lần. Để tránh gây quá tải cho website, vui lòng chờ một lúc rồi quét lại.",
};

/**
 * Validate the target, run SSRF checks (including a DNS preflight over DoH), enforce rate limits atomically
 * in D1, and enqueue the scan. The authoritative DNS check + connection pinning happens again in the scanner
 * container; this preflight just fails fast on obviously bad targets before they consume queue capacity.
 */
export async function createScan(db: D1Like, userId: string, rawUrl: string, ipHash: string | null, resolver: Resolver): Promise<CreateScanResult> {
  let target;
  try {
    target = normalizeTargetUrl(rawUrl);
    await resolvePublicAddresses(target.host, resolver);
  } catch (e) {
    if (e instanceof SsrfError) {
      // Only NXDOMAIN is a hard "doesn't exist". Resolver hiccups fall through; the container re-validates.
      const transientDns = e.code === "dns_failed" && e.detail !== "ENOTFOUND";
      if (!transientDns) {
        if (e.code !== "dns_failed") await recordSsrfStrike(db, userId, { code: e.code, stage: e.code === "non_public_ip" || e.code === "dns_mixed_answers" ? "dns" : "input", host: stripQuery(rawUrl) });
        return { ok: false, status: 400, code: e.code, message: e.message };
      }
    } else throw e;
    target ??= normalizeTargetUrl(rawUrl);
  }

  if (await repo.userBlocked(db, userId)) { /* để createScanChecked trả account_blocked */ }
  else {
    const cachedId = await repo.cloneRecentScan(db, { userId, url: target.url, host: target.host, ipHash });
    if (cachedId) {
      await repo.recordEvent(db, { type: "scan_cached", userId, scanId: cachedId, meta: { host: target.host } });
      return { ok: true, id: cachedId, cached: true };
    }
  }

  const out = await repo.createScanChecked(db, {
    userId, url: target.url, host: target.host, ipHash,
    limits: { maxConcurrent: env.limits.maxConcurrentPerUser, hourly: env.limits.hourlyLimit, daily: env.limits.dailyQuota, monthly: env.limits.monthlyQuota, globalDaily: env.limits.globalDailyCap, ipHourly: env.limits.ipHourlyLimit, hostHourly: env.limits.hostHourlyLimit },
  });
  if (!out.ok) {
    await repo.recordEvent(db, { type: "rate_limited", userId, level: "warn", message: out.code, meta: { code: out.code, host: target.host } });
    return { ok: false, status: out.code === "account_blocked" ? 403 : 429, code: out.code, message: LIMIT_MESSAGES[out.code] ?? "Đã đạt giới hạn quét.", retryAfter: out.retryAfter };
  }
  await repo.recordEvent(db, { type: "scan_created", userId, scanId: out.id, meta: { host: target.host } });
  return { ok: true, id: out.id };
}
