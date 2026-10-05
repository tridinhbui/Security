import type { FetchRecord } from "../ssrf/types";
import type { ScanBudget } from "../ssrf/budget";
import type { NormalizedTarget } from "../ssrf/url";
import { attachFixCommands } from "./fixes";
import { ENGINE_VERSION } from "./version";
import { ALL_RULES } from "./rules";
import { evaluate } from "./evaluate";
import { redactHeaders, type RedactedTarget, type ScanReport } from "./report";
import { calculateScore, prioritize, SCORE_DISCLAIMER, topRisks } from "./score";
import type { Observations } from "./types";

/** Phần thuần (không I/O) của một lượt quét: Observations → báo cáo. Dùng chung cho container và Worker. */
export function targetsFrom(obs: Observations): RedactedTarget[] {
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

export function buildReport(input: string, target: NormalizedTarget, obs: Observations, budget: ScanBudget, started: number, quick = false): ScanReport {
  const { findings: raw, errors } = evaluate(obs);
  const findings = attachFixCommands(raw, { host: target.host, platforms: obs.platforms });
  const score = calculateScore(findings, { limitedCoverage: quick || obs.limits.hitLimit !== null });
  return {
    version: 1,
    engineVersion: ENGINE_VERSION,
    target: { input, url: target.url, host: target.host },
    scannedAt: obs.scannedAt,
    durationMs: Date.now() - started,
    score,
    findings: prioritize(findings),
    topRisks: topRisks(findings),
    platforms: obs.platforms,
    technologies: obs.technologies,
    targets: targetsFrom(obs),
    stats: { requests: budget.used, hitLimit: obs.limits.hitLimit, rulesRun: ALL_RULES.length, ruleErrors: errors, ...(quick ? { quick: true } : {}) },
    disclaimer: SCORE_DISCLAIMER,
  };
}
