import type { D1Like } from "../db/d1";
import * as repo from "../db/repo";
import { ScanBudget } from "../ssrf/budget";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "../ssrf/dns";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { createWorkerFetcher } from "../ssrf/worker-fetch";
import { collect } from "../scanner/collect-core";
import { createDohDnsLookup } from "../scanner/dns-doh";
import { buildReport } from "../scanner/pipeline";
import { ScanRefusedError } from "../scanner/report";
import type { TlsInspection } from "../scanner/tls-inspect";
import { createNdjsonScanner, requestTls, type ScannerClient } from "./scanner-client";

export interface HybridDeps {
  db: D1Like;
  /** DoH (Worker). */
  resolver: Resolver;
  /** Gửi request tới container (chỉ dùng cho /tls và đường dự phòng /scan). Container chỉ được đánh thức khi gọi hàm này. */
  container: (req: Request) => Promise<Response>;
  fetchImpl?: typeof fetch;
  denyHosts?: string[];
}

/** Chứng chỉ còn đủ lâu và hợp lệ thì dùng lại kết quả TLS đã lưu; ngược lại hỏi container để có số liệu mới nhất. */
const cacheUsable = (c: TlsInspection | null): c is TlsInspection => !!c && c.ok === true && !c.certError && (c.tls.daysRemaining ?? 0) > 14;

/**
 * Quét lai: Worker làm toàn bộ phần HTTP/HTML/cookie/DNS (gần như miễn phí); container chỉ bắt tay TLS (~vài giây, có đệm 12 giờ).
 * Nếu Worker không tự đánh giá được trang qua HTTPS (chứng chỉ hỏng, lỗi mạng…) thì chuyển sang bộ quét đầy đủ trong container
 * để kết quả vẫn chính xác như trước.
 */
export function createHybridScanner(d: HybridDeps): ScannerClient {
  const full = createNdjsonScanner(d.container);
  const dnsCache = new Map<string, { at: number; addrs: ResolvedAddress[] }>();
  return {
    async scan(url, onStage, opts) {
      const started = Date.now();
      const quick = opts?.quick === true;
      await onStage("validating");
      let target;
      try {
        target = normalizeTargetUrl(url);
        await resolvePublicAddresses(target.host, d.resolver, dnsCache);
      } catch (e) {
        if (e instanceof SsrfError) throw new ScanRefusedError(e.code, e.message, e.detail);
        throw e;
      }

      const budget = new ScanBudget(34, 8 * 1024 * 1024, 70_000);
      const safeFetch = createWorkerFetcher(budget, { resolver: d.resolver, dnsCache, fetchImpl: d.fetchImpl, denyHosts: d.denyHosts });
      const obs = await collect(target, url, { fetch: safeFetch, budget, quick, lookupDns: createDohDnsLookup(d.fetchImpl ?? fetch), onStage: (s) => onStage(s) });

      const blocked = obs.https?.error?.blocked ? obs.https.error : obs.http?.error?.blocked ? obs.http.error : null;
      if (!obs.page && blocked) throw new ScanRefusedError(blocked.code, blocked.message, blocked.detail);
      // HTTPS lỗi mà không phải do bị chặn (chứng chỉ hỏng, cổng đóng…) → để container (có tolerateBadCert + ghim IP) quyết định.
      if (!obs.page || (obs.https?.error && !obs.https.error.blocked)) return full.scan(url, onStage, opts);

      if (obs.https && !obs.https.error) {
        const host = target.host;
        let ins = await repo.getTlsCache<TlsInspection>(d.db, host);
        if (!cacheUsable(ins)) {
          const reply = await requestTls(d.container, host);
          if ("refused" in reply) throw new ScanRefusedError(reply.refused.code, reply.refused.message, reply.refused.detail);
          ins = reply.ok ? reply : null;
          if (ins) await repo.putTlsCache(d.db, host, ins).catch(() => undefined);
        }
        if (ins) {
          obs.https.tls = ins.tls;
          if (ins.certError) obs.https.certError = ins.certError;
          obs.legacyTls = ins.legacyTls;
        }
      }

      await onStage("generating_report");
      return buildReport(url, target, obs, budget, started, quick);
    },
  };
}
