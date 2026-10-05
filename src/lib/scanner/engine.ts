import { createSafeFetcher, ScanBudget } from "../ssrf/fetch";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "../ssrf/dns";
import { systemResolver } from "../ssrf/dns-node";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { collect, type CollectDeps, type ScanStage } from "./collect";
import { evaluate } from "./evaluate";
import { buildReport } from "./pipeline";
import { redactHeaders, ScanRefusedError, type RedactedTarget, type ScanReport } from "./report";

export interface RunScanOptions {
  onStage?: CollectDeps["onStage"];
  budget?: ScanBudget;
  resolver?: Resolver;
  dnsCache?: Map<string, { at: number; addrs: ResolvedAddress[] }>;
  collectOverrides?: Partial<CollectDeps>;
  testRoutes?: Record<string, { port: number }>;
  quick?: boolean;
}

/** Shared DNS validation cache (5-minute TTL enforced in resolvePublicAddresses). */
const sharedDnsCache = new Map<string, { at: number; addrs: ResolvedAddress[] }>();

export async function runScan(input: string, opts: RunScanOptions = {}): Promise<ScanReport> {
  const started = Date.now();
  await opts.onStage?.("validating");
  let target;
  try {
    target = normalizeTargetUrl(input);
    const route = opts.testRoutes?.[target.host];
    if (!route) await resolvePublicAddresses(target.host, opts.resolver ?? systemResolver, opts.dnsCache ?? sharedDnsCache);
  } catch (e) {
    if (e instanceof SsrfError) throw new ScanRefusedError(e.code, e.message, e.detail);
    throw e;
  }

  const budget = opts.budget ?? new ScanBudget(34, 8 * 1024 * 1024, 70_000);
  const fetch = createSafeFetcher(budget, { resolver: opts.resolver, dnsCache: opts.dnsCache ?? sharedDnsCache, testRoutes: opts.testRoutes });
  const obs = await collect(target, input, { fetch, budget, onStage: opts.onStage, quick: opts.quick, ...opts.collectOverrides });

  if (!obs.page) {
    const err = obs.https?.error ?? obs.http?.error;
    if (err?.blocked) throw new ScanRefusedError(err.code, err.message, err.detail);
    throw new ScanRefusedError("unreachable", "Không kết nối được tới website này qua HTTPS lẫn HTTP. Hãy kiểm tra địa chỉ và chắc chắn website đang hoạt động, rồi thử lại.", err?.code);
  }

  await opts.onStage?.("generating_report");
  return buildReport(input, target, obs, budget, started, opts.quick);
}

export { evaluate, ScanRefusedError, redactHeaders };
export type { ScanStage, ScanReport, RedactedTarget };
