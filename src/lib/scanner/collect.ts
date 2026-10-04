import dns from "node:dns/promises";
import tls from "node:tls";
import { getDomain } from "tldts";
import { BudgetError, type FetchRecord, type SafeFetch, type ScanBudget } from "../ssrf/fetch";
import type { NormalizedTarget } from "../ssrf/url";
import { fingerprint } from "./fingerprint";
import { parseHtml } from "./parse";
import type { CorsProbe, DnsInfo, FileProbe, Observations, ScriptRef, SourceMapProbe } from "./types";
import { header, isHtml } from "./util";

export type ScanStage = "validating" | "scanning_transport" | "checking_headers" | "analyzing_client" | "generating_report";

export interface CollectDeps {
  fetch: SafeFetch;
  budget: ScanBudget;
  onStage?: (s: ScanStage) => void | Promise<void>;
  /** Overridable for tests. */
  probeLegacyTls?: (host: string, ip: string, version: "TLSv1" | "TLSv1.1") => Promise<boolean | null>;
  lookupDns?: (domain: string, host: string) => Promise<DnsInfo>;
}

const PROBE_ORIGIN = "https://vibesec-cors-probe.invalid";
const SENSITIVE_PATH = /\/(login|log-in|signin|sign-in|account|admin|dashboard|wp-login\.php|auth)(\/|$|\?)/i;
const LOW_VALUE_SCRIPT = /(polyfill|webpack-|runtime-|google-analytics|googletagmanager|gtag|analytics|hotjar|segment|intercom|fbevents|pixel)/i;
const MAX_SCRIPTS = 6;
const MAX_SOURCE_MAPS = 3;

// ------------------------------------------------------------------ DNS metadata (short TTL cache)

const dnsCache = new Map<string, { at: number; value: DnsInfo }>();
const DNS_TTL_MS = 5 * 60_000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    p.then((v) => (clearTimeout(t), resolve(v)), (e) => (clearTimeout(t), reject(e)));
  });
}

export async function lookupDnsMetadata(domain: string): Promise<DnsInfo> {
  const hit = dnsCache.get(domain);
  if (hit && Date.now() - hit.at < DNS_TTL_MS) return hit.value;
  const txt = async (name: string): Promise<string[] | undefined> => {
    try {
      return (await withTimeout(dns.resolveTxt(name), 3000)).map((r) => r.join(""));
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      return code === "ENODATA" || code === "ENOTFOUND" ? [] : undefined;
    }
  };
  const [txts, dmarcTxts, caa] = await Promise.all([
    txt(domain),
    txt(`_dmarc.${domain}`),
    withTimeout(dns.resolveCaa(domain), 3000).then((r) => r.map((x) => `${x.critical} ${"issue" in x ? `issue "${x.issue}"` : "issuewild" in x ? `issuewild "${x.issuewild}"` : "iodef"}`)).catch((e: NodeJS.ErrnoException) => (e.code === "ENODATA" || e.code === "ENOTFOUND" ? [] : null)),
  ]);
  const value: DnsInfo = {
    domain,
    caa,
    spf: txts === undefined ? undefined : (txts.find((t) => /^v=spf1\b/i.test(t)) ?? null),
    dmarc: dmarcTxts === undefined ? undefined : (dmarcTxts.find((t) => /^v=DMARC1\b/i.test(t)) ?? null),
  };
  dnsCache.set(domain, { at: Date.now(), value });
  return value;
}

// ------------------------------------------------------------------ legacy TLS probe

/**
 * Returns true ONLY if a handshake restricted to the legacy version succeeded (proof the server
 * accepts it). Any error/timeout returns false/null, so this can never create a false positive.
 * Connects to an already-validated public IP; no DNS is performed.
 */
export function probeLegacyTlsVersion(host: string, ip: string, version: "TLSv1" | "TLSv1.1"): Promise<boolean | null> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(v);
    };
    const socket = tls.connect({ host: ip, port: 443, servername: host, minVersion: version, maxVersion: version, ciphers: "ALL:@SECLEVEL=0", rejectUnauthorized: false }, () => {
      socket.destroy();
      finish(true);
    });
    const timer = setTimeout(() => {
      socket.destroy();
      finish(null);
    }, 4000);
    socket.on("error", () => finish(false));
  });
}

// ------------------------------------------------------------------ helpers

const ok = (r: FetchRecord | null): r is FetchRecord => !!r && !r.error && r.status !== null;

function toFileProbe(url: string, r: FetchRecord, kind: "robots" | "sitemap" | "security"): FileProbe {
  const base: FileProbe = { url, present: false, status: r.status, contentType: r.contentType, body: r.body.slice(0, 64 * 1024), error: r.error?.code };
  if (r.error || r.status !== 200 || !r.body.trim()) return base;
  // Single-page apps often answer every path with the HTML shell and a 200 — that is NOT a real file.
  if (isHtml(r.contentType) || /^\s*<!doctype html|^\s*<html/i.test(r.body)) return base;
  if (kind === "robots") base.present = /user-agent|disallow|allow|sitemap/i.test(r.body);
  else if (kind === "sitemap") base.present = /<(urlset|sitemapindex)\b/i.test(r.body) || r.contentType.includes("xml");
  else base.present = /^\s*(contact|expires)\s*:/im.test(r.body);
  return base;
}

function pickScripts(scripts: ScriptRef[]): ScriptRef[] {
  const seen = new Set<string>();
  const candidates = scripts.filter((s) => !s.inline && s.sameOrigin && s.url && !seen.has(s.url) && (seen.add(s.url), true));
  const score = (s: ScriptRef) => (LOW_VALUE_SCRIPT.test(s.url!) ? 1 : 0);
  return candidates.sort((a, b) => score(a) - score(b)).slice(0, MAX_SCRIPTS);
}

async function inBatches<T>(items: T[], size: number, fn: (t: T) => Promise<void>) {
  for (let i = 0; i < items.length; i += size) await Promise.all(items.slice(i, i + size).map(fn));
}

// ------------------------------------------------------------------ the collector

export async function collect(target: NormalizedTarget, input: string, deps: CollectDeps): Promise<Observations> {
  const { fetch: get, budget } = deps;
  const stage = async (s: ScanStage) => void (await deps.onStage?.(s));
  const originHttps = `https://${target.host}`;
  const originHttp = `http://${target.host}`;
  const pathPart = target.path + "";

  const obs: Observations = {
    target: { input, url: target.url, origin: target.origin, host: target.host, scheme: target.scheme },
    https: null, http: null, page: null, pageIsHttps: false, html: null, scripts: [], sourceMaps: [],
    files: { robots: null, sitemap: null, securityTxt: null }, cors: null, sensitivePage: null, dns: null, legacyTls: null,
    platforms: [], technologies: [], limits: { requestsUsed: 0, hitLimit: null },
    scannedAt: new Date().toISOString(),
  };
  const noteLimit = (r: FetchRecord | null) => {
    const c = r?.error?.code;
    if (c === "request_budget" || c === "deadline" || c === "byte_budget") obs.limits.hitLimit ??= c;
  };

  // ---- transport
  await stage("scanning_transport");
  [obs.https, obs.http] = await Promise.all([
    get(originHttps + pathPart, { tolerateBadCert: true, maxBytes: 768 * 1024 }),
    get(originHttp + pathPart, { maxBytes: 128 * 1024 }),
  ]);
  noteLimit(obs.https); noteLimit(obs.http);

  const domain = getDomain(target.host);
  const probe = deps.probeLegacyTls ?? probeLegacyTlsVersion;
  const dnsJob = domain ? (deps.lookupDns ?? ((d: string) => lookupDnsMetadata(d)))(domain, target.host).catch(() => null) : Promise.resolve(null);
  let legacyJob: Promise<Observations["legacyTls"]> = Promise.resolve(null);
  const ip = obs.https?.resolved[0];
  if (ok(obs.https) && !obs.https.certError && ip) {
    legacyJob = (async () => {
      try { budget.take(); budget.take(); } catch { return null; }
      const [tls10, tls11] = await Promise.all([probe(target.host, ip, "TLSv1"), probe(target.host, ip, "TLSv1.1")]);
      return { tls10, tls11 };
    })();
  }
  [obs.dns, obs.legacyTls] = await Promise.all([dnsJob, legacyJob]);

  // ---- choose the page to analyse
  const page = ok(obs.https) ? obs.https : ok(obs.http) ? obs.http : null;
  obs.page = page;
  obs.pageIsHttps = !!page && page.finalUrl.startsWith("https://");
  if (page && isHtml(page.contentType)) obs.html = parseHtml(page.body, page.finalUrl);
  const fp = fingerprint(page?.headers, page?.body ?? "", obs.html);
  obs.platforms = fp.platforms;
  obs.technologies = fp.technologies;

  if (!page) {
    obs.limits.requestsUsed = budget.used;
    return obs; // nothing more can be observed; rules will report what they can
  }

  // ---- headers & well-known files
  await stage("checking_headers");
  const pageOrigin = new URL(page.finalUrl).origin;
  const fileJobs = await Promise.all([
    get(`${pageOrigin}/robots.txt`, { maxBytes: 64 * 1024, timeoutMs: 6000 }),
    get(`${pageOrigin}/sitemap.xml`, { maxBytes: 64 * 1024, timeoutMs: 6000 }),
    get(`${pageOrigin}/.well-known/security.txt`, { maxBytes: 32 * 1024, timeoutMs: 6000 }),
  ]);
  fileJobs.forEach(noteLimit);
  obs.files.robots = toFileProbe(`${pageOrigin}/robots.txt`, fileJobs[0], "robots");
  obs.files.sitemap = toFileProbe(`${pageOrigin}/sitemap.xml`, fileJobs[1], "sitemap");
  obs.files.securityTxt = toFileProbe(`${pageOrigin}/.well-known/security.txt`, fileJobs[2], "security");
  if (!obs.files.securityTxt.present && !fileJobs[2].error?.blocked) {
    const legacy = await get(`${pageOrigin}/security.txt`, { maxBytes: 32 * 1024, timeoutMs: 6000 });
    noteLimit(legacy);
    const probeLegacy = toFileProbe(`${pageOrigin}/security.txt`, legacy, "security");
    if (probeLegacy.present) obs.files.securityTxt = probeLegacy;
  }

  // CORS: one request with a clearly synthetic Origin. We only read response headers.
  const corsRec = await get(page.finalUrl, { headers: { origin: PROBE_ORIGIN }, maxBytes: 1024, timeoutMs: 8000, followRedirects: false });
  noteLimit(corsRec);
  if (!corsRec.error) {
    obs.cors = { testedOrigin: PROBE_ORIGIN, status: corsRec.status, acao: header(corsRec.headers, "access-control-allow-origin") ?? null, acac: header(corsRec.headers, "access-control-allow-credentials") ?? null, vary: header(corsRec.headers, "vary") ?? null } satisfies CorsProbe;
  }

  // ---- client resources
  await stage("analyzing_client");
  if (obs.html) {
    const scripts = obs.html.scripts;
    const chosen = pickScripts(scripts);
    await inBatches(chosen, 3, async (s) => {
      try {
        const rec = await get(s.url!, { maxBytes: 1_500_000, timeoutMs: 10_000, headers: { accept: "*/*" } });
        noteLimit(rec);
        if (!rec.error && rec.status === 200) {
          s.fetched = rec;
          s.content = rec.body;
        }
      } catch (e) {
        if (!(e instanceof BudgetError)) throw e;
      }
    });
    obs.scripts = scripts; // inline + external (only chosen ones carry fetched bodies)

    const maps: SourceMapProbe[] = [];
    const mapTargets: { scriptUrl: string; mapUrl: string }[] = [];
    for (const s of chosen) {
      if (!s.fetched) continue;
      const tail = s.fetched.body.slice(-2048);
      const ref = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(tail)?.[1] ?? header(s.fetched.headers, "sourcemap") ?? header(s.fetched.headers, "x-sourcemap");
      if (!ref || ref.startsWith("data:")) continue;
      try {
        const mapUrl = new URL(ref, s.url!).href;
        if (new URL(mapUrl).origin === pageOrigin && mapTargets.length < MAX_SOURCE_MAPS) mapTargets.push({ scriptUrl: s.url!, mapUrl });
      } catch { /* invalid reference */ }
    }
    await inBatches(mapTargets, 3, async (m) => {
      const rec = await get(m.mapUrl, { maxBytes: 4096, timeoutMs: 8000, headers: { accept: "application/json,*/*" } });
      noteLimit(rec);
      const looksLikeMap = rec.status === 200 && /"version"\s*:\s*3/.test(rec.body) && /"(sources|mappings)"/.test(rec.body);
      maps.push({ ...m, exposed: looksLikeMap, status: rec.status });
    });
    obs.sourceMaps = maps;

    // One login/account-looking same-origin page for cache and cookie checks.
    const sensitive = obs.html.anchors.find((a) => SENSITIVE_PATH.test(new URL(a).pathname + "/") && new URL(a).pathname !== new URL(page.finalUrl).pathname);
    if (sensitive) {
      const rec = await get(sensitive, { maxBytes: 256 * 1024, timeoutMs: 8000 });
      noteLimit(rec);
      if (!rec.error) obs.sensitivePage = rec;
    }
  }

  obs.limits.requestsUsed = budget.used;
  return obs;
}
