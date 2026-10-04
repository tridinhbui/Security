import { createSafeFetcher, ScanBudget, type FetchRecord } from "../ssrf/fetch";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "../ssrf/dns";
import { systemResolver } from "../ssrf/dns-node";
import { normalizeTargetUrl, SsrfError } from "../ssrf/url";
import { collect, type CollectDeps, type ScanStage } from "./collect";
import { ALL_RULES } from "./rules";
import { evaluate } from "./evaluate";
import { redactHeaders, ScanRefusedError, type RedactedTarget, type ScanReport } from "./report";
import { calculateScore, prioritize, SCORE_DISCLAIMER, topRisks, type ScoreResult } from "./score";
import type { Finding, Observations, Platform, Rule } from "./types";

function targetsFrom(obs: Observations): RedactedTarget[] {
  const t: RedactedTarget[] = [];
  const add = (role: string, r: FetchRecord | null) => {
    if (!r) return;
    t.push({ role, url: r.requestedUrl, finalUrl: r.finalUrl, status: r.status, tls: r.tls, headers: redactHeaders(r.headers), resolved: r.resolved, errorCode: r.error?.code ?? r.certError?.code, durationMs: r.durationMs });
  };
  add("https_home", obs.https);
  add("http_home", obs.http);
  add("sensitive_page", obs.sensitivePage);
  for (const s of obs.scripts) if (s.fetched) add("script", s.fetched);
  return t;
}

export interface RunScanOptions {
  onStage?: CollectDeps["onStage"];
  budget?: ScanBudget;
  resolver?: Resolver;
  dnsCache?: Map<string, { at: number; addrs: ResolvedAddress[] }>;
  collectOverrides?: Partial<CollectDeps>;
  testRoutes?: Record<string, { port: number }>;
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
  const obs = await collect(target, input, { fetch, budget, onStage: opts.onStage, ...opts.collectOverrides });

  if (!obs.page) {
    const err = obs.https?.error ?? obs.http?.error;
    if (err?.blocked) throw new ScanRefusedError(err.code, err.message, err.detail);
    throw new ScanRefusedError("unreachable", "Không kết nối được tới website này qua HTTPS lẫn HTTP. Hãy kiểm tra địa chỉ và chắc chắn website đang hoạt động, rồi thử lại.", err?.code);
  }

  await opts.onStage?.("generating_report");
  const { findings, errors } = evaluate(obs);
  const score = calculateScore(findings);
  const ordered = prioritize(findings);
  return {
    version: 1,
    target: { input, url: target.url, host: target.host },
    scannedAt: obs.scannedAt,
    durationMs: Date.now() - started,
    score,
    findings: ordered,
    topRisks: topRisks(findings),
    platforms: obs.platforms,
    technologies: obs.technologies,
    targets: targetsFrom(obs),
    stats: { requests: budget.used, hitLimit: obs.limits.hitLimit, rulesRun: ALL_RULES.length, ruleErrors: errors },
    disclaimer: SCORE_DISCLAIMER,
  };
}

export { evaluate, ScanRefusedError, redactHeaders };
export type { ScanStage, ScanReport, RedactedTarget };
