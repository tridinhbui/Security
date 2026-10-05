import dns from "node:dns/promises";
import tls from "node:tls";
import type { DnsInfo, Observations } from "./types";
import type { NormalizedTarget } from "../ssrf/url";
import { collect as collectCore, type CollectDeps } from "./collect-core";

export { alternateHost, type CollectDeps, type ScanStage } from "./collect-core";

// ------------------------------------------------------------------ DNS metadata (cache ngắn)

const dnsCache = new Map<string, { at: number; value: DnsInfo }>();
const DNS_TTL_MS = 5 * 60_000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    p.then((v) => (clearTimeout(t), resolve(v)), (e) => (clearTimeout(t), reject(e)));
  });
}

const noData = (e: unknown) => ["ENODATA", "ENOTFOUND", "NXDOMAIN"].includes((e as NodeJS.ErrnoException).code ?? "");

/** DNSSEC: hỏi bộ phân giải công cộng của Cloudflare (không phải máy chủ của mục tiêu); cờ AD = đã xác thực. */
async function lookupDnssec(domain: string): Promise<boolean | undefined> {
  try {
    const res = await withTimeout(fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A&do=1`, { headers: { accept: "application/dns-json" } }), 4000);
    if (!res.ok) return undefined;
    const body = (await res.json()) as { Status?: number; AD?: boolean };
    return body.Status === 0 ? body.AD === true : undefined;
  } catch {
    return undefined;
  }
}

export async function lookupDnsMetadata(domain: string, host: string = domain): Promise<DnsInfo> {
  const key = `${domain}|${host}`;
  const hit = dnsCache.get(key);
  if (hit && Date.now() - hit.at < DNS_TTL_MS) return hit.value;
  const txt = async (name: string): Promise<string[] | undefined> => {
    try {
      return (await withTimeout(dns.resolveTxt(name), 3000)).map((r) => r.join(""));
    } catch (e) {
      return noData(e) ? [] : undefined;
    }
  };
  const list = async <T>(p: Promise<T[]>): Promise<T[] | null> => withTimeout(p, 3000).catch((e) => (noData(e) ? [] : null));
  const [txts, dmarcTxts, mtaTxts, caa, cname, mx, ns, dnssec] = await Promise.all([
    txt(domain),
    txt(`_dmarc.${domain}`),
    txt(`_mta-sts.${domain}`),
    list(dns.resolveCaa(domain)).then((r) => r && r.map((x) => `${x.critical} ${"issue" in x ? `issue "${x.issue}"` : "issuewild" in x ? `issuewild "${x.issuewild}"` : "iodef"}`)),
    list(dns.resolveCname(host)),
    list(dns.resolveMx(domain)).then((r) => r && r.map((x) => x.exchange)),
    list(dns.resolveNs(domain)),
    lookupDnssec(domain),
  ]);
  const spfAll = txts?.filter((t) => /^v=spf1\b/i.test(t)) ?? [];
  const value: DnsInfo = {
    domain,
    caa,
    spf: txts === undefined ? undefined : (spfAll[0] ?? null),
    spfRecords: spfAll.length,
    dmarc: dmarcTxts === undefined ? undefined : (dmarcTxts.find((t) => /^v=DMARC1\b/i.test(t)) ?? null),
    mtaSts: mtaTxts === undefined ? undefined : mtaTxts.some((t) => /^v=STSv1\b/i.test(t)),
    cname: cname && cname.length ? cname : null,
    mx,
    ns,
    dnssec,
  };
  dnsCache.set(key, { at: Date.now(), value });
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

/** Có thương lượng được HTTP/2 qua ALPN không? (true/false; null nếu không kết nối được). */
export function probeHttp2(host: string, ip: string): Promise<boolean | null> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean | null) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const socket = tls.connect({ host: ip, port: 443, servername: host, ALPNProtocols: ["h2", "http/1.1"], rejectUnauthorized: false }, () => {
      const proto = socket.alpnProtocol;
      socket.destroy();
      finish(proto === "h2");
    });
    const timer = setTimeout(() => { socket.destroy(); finish(null); }, 4000);
    socket.on("error", () => finish(null));
  });
}


/** Bản chạy trong container: dùng phân giải DNS của hệ thống và các thăm dò TLS bằng node:tls. */
export function collect(target: NormalizedTarget, input: string, deps: CollectDeps): Promise<Observations> {
  return collectCore(target, input, { probeLegacyTls: probeLegacyTlsVersion, probeHttp2, lookupDns: lookupDnsMetadata, ...deps });
}
