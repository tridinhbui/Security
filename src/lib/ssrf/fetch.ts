import { X509Certificate } from "node:crypto";
import http from "node:http";
import https from "node:https";
import type { TLSSocket } from "node:tls";
import { pinnedLookup, resolvePublicAddresses, type ResolvedAddress, type Resolver } from "./dns";
import { systemResolver } from "./dns-node";
import { SsrfError, validateRequestUrl } from "./url";

export const USER_AGENT = "VibeSecBot/1.0 (+https://vibesec.app/bot; passive, non-destructive security audit)";

import type { FetchRecord, Headers, HttpHop, TlsInfo } from "./types";
export type { FetchRecord, Headers, HttpHop, TlsInfo };

export type BudgetErrorCode = "request_budget" | "deadline" | "byte_budget";
export class BudgetError extends Error {
  constructor(public readonly code: BudgetErrorCode, message: string) {
    super(message);
    this.name = "BudgetError";
  }
}

/** Hard ceilings for one scan. Shared by every request the scan makes. */
export class ScanBudget {
  used = 0;
  bytes = 0;
  readonly deadline: number;
  constructor(
    readonly maxRequests = 20,
    readonly maxTotalBytes = 6 * 1024 * 1024,
    readonly maxDurationMs = 60_000,
    now = Date.now(),
  ) {
    this.deadline = now + maxDurationMs;
  }
  remainingMs() {
    return this.deadline - Date.now();
  }
  take() {
    if (this.remainingMs() <= 0) throw new BudgetError("deadline", "Đã hết thời gian quét tối đa.");
    if (this.used >= this.maxRequests) throw new BudgetError("request_budget", "Đã đạt giới hạn số request cho một lần quét.");
    if (this.bytes >= this.maxTotalBytes) throw new BudgetError("byte_budget", "Đã đạt giới hạn dung lượng tải cho một lần quét.");
    this.used++;
  }
  addBytes(n: number) {
    this.bytes += n;
  }
}

export interface FetchOptions {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  followRedirects?: boolean;
  /** Retry once without certificate verification if the cert is invalid, so headers can still be audited. */
  tolerateBadCert?: boolean;
}

export interface FetcherDeps {
  /**
   * TEST ONLY. Maps specific fake hostnames to a loopback port so unit tests can exercise
   * the HTTP client against a local server. Hosts not listed here get full SSRF validation.
   * Construction throws when NODE_ENV=production.
   */
  testRoutes?: Record<string, { port: number }>;
  resolver?: Resolver;
  dnsCache?: Map<string, { at: number; addrs: ResolvedAddress[] }>;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const CERT_ERRORS = new Set([
  "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_NOT_YET_VALID", "CERT_REVOKED",
]);

interface HopResult {
  status: number;
  headers: Headers;
  body: Buffer;
  truncated: boolean;
  tls?: TlsInfo;
}

function describeCert(socket: TLSSocket): TlsInfo {
  const cert = socket.getPeerCertificate(true);
  const info: TlsInfo = {
    protocol: socket.getProtocol(),
    cipher: socket.getCipher()?.name ?? null,
    authorized: socket.authorized,
    authError: socket.authorizationError ? String(socket.authorizationError) : undefined,
  };
  if (cert && Object.keys(cert).length) {
    info.validFrom = cert.valid_from;
    info.validTo = cert.valid_to;
    const to = Date.parse(cert.valid_to);
    const from = Date.parse(cert.valid_from);
    if (!Number.isNaN(to)) info.daysRemaining = Math.floor((to - Date.now()) / 86_400_000);
    if (!Number.isNaN(to) && !Number.isNaN(from)) info.validityDays = Math.round((to - from) / 86_400_000);
    info.issuer = [cert.issuer?.O ?? cert.issuer?.CN].flat()[0];
    info.subject = [cert.subject?.CN].flat()[0];
    info.altNames = cert.subjectaltname?.split(",").map((s) => s.trim().replace(/^DNS:/, "")).slice(0, 25);
    info.wildcard = info.altNames?.some((n) => n.startsWith("*.")) ?? false;
    try {
      const x = new X509Certificate(cert.raw);
      info.keyType = x.publicKey.asymmetricKeyType ?? undefined;
      const d = x.publicKey.asymmetricKeyDetails;
      info.keyBits = d?.modulusLength ?? (typeof cert.bits === "number" ? cert.bits : undefined);
      info.curve = d?.namedCurve;
      info.selfSigned = x.verify(x.publicKey);
    } catch { /* thông tin khoá là phần bổ sung; bỏ qua nếu không đọc được */ }
    let depth = 1, cur = cert;
    while (cur.issuerCertificate && cur.issuerCertificate !== cur && depth < 10) { cur = cur.issuerCertificate; depth++; }
    info.chainLength = depth;
  }
  return info;
}

function requestOnce(
  url: URL,
  addrs: ResolvedAddress[],
  o: Required<Pick<FetchOptions, "method" | "maxBytes">> & {
    headers: Record<string, string>;
    timeoutMs: number;
    rejectUnauthorized: boolean;
    testPort?: number;
  },
  skipRedirectBody: boolean,
): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(hard);
      fn();
    };
    const lib = isHttps ? https : http;
    const req = lib.request(
      {
        hostname,
        port: o.testPort ?? (url.port || (isHttps ? 443 : 80)),
        path: url.pathname + url.search,
        method: o.method,
        agent: false, // no connection reuse: every request is separately pinned and validated
        lookup: pinnedLookup(addrs, o.testPort !== undefined) as never,
        servername: /^[\d.]+$/.test(hostname) || hostname.includes(":") ? undefined : hostname,
        rejectUnauthorized: o.rejectUnauthorized,
        headers: {
          host: url.host,
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
          "accept-encoding": "identity", // never decompress: removes decompression-bomb risk
          connection: "close",
          ...o.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        const tls = isHttps ? describeCert(res.socket as TLSSocket) : undefined;
        const headers: Headers = {};
        for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = v as string | string[];
        const finish = () =>
          done(() => resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks), truncated, tls }));

        const isRedirect = REDIRECT_STATUSES.has(res.statusCode ?? 0) && typeof res.headers.location === "string";
        if ((skipRedirectBody && isRedirect) || o.method === "HEAD") {
          res.destroy();
          return finish();
        }
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > o.maxBytes) {
            const keep = c.length - (size - o.maxBytes);
            if (keep > 0) chunks.push(c.subarray(0, keep));
            truncated = true;
            res.destroy();
            return finish();
          }
          chunks.push(c);
        });
        res.on("end", finish);
        res.on("close", finish);
        res.on("error", (e) => (truncated || size > 0 ? finish() : done(() => reject(e))));
      },
    );
    // Hard wall-clock limit for the whole request (defeats slow-drip responses).
    const hard = setTimeout(() => {
      const e = new Error("Request timed out") as NodeJS.ErrnoException;
      e.code = "ETIMEDOUT";
      req.destroy(e);
      done(() => reject(e));
    }, o.timeoutMs);
    req.on("error", (e) => done(() => reject(e)));
    req.end();
  });
}

/**
 * Create a fetcher bound to a ScanBudget. Every hop — including redirects — is
 * re-validated (scheme, port, hostname, DNS answers) and pinned to the validated IPs.
 * Never throws for network/SSRF problems: failures are reported in `record.error`.
 */
export function createSafeFetcher(budget: ScanBudget, deps: FetcherDeps = {}) {
  const resolver = deps.resolver ?? systemResolver;
  const dnsCache = deps.dnsCache;
  const testRoutes = deps.testRoutes;
  if (testRoutes && process.env.NODE_ENV === "production") {
    throw new Error("testRoutes must never be used in production");
  }

  return async function safeFetch(rawUrl: string, opts: FetchOptions = {}): Promise<FetchRecord> {
    const started = Date.now();
    const maxBytes = opts.maxBytes ?? 1024 * 1024;
    const maxRedirects = opts.maxRedirects ?? 5;
    const follow = opts.followRedirects ?? true;
    const method = opts.method ?? "GET";
    const record: FetchRecord = {
      requestedUrl: rawUrl, finalUrl: rawUrl, status: null, headers: {}, chain: [], body: "", bytes: 0,
      truncated: false, contentType: "", resolved: [], durationMs: 0,
    };
    const fail = (code: string, message: string, extra: Partial<NonNullable<FetchRecord["error"]>> = {}) => {
      record.error = { code, message, ...extra };
      record.durationMs = Date.now() - started;
      return record;
    };

    let current = rawUrl;
    const seen = new Set<string>();
    for (let hop = 0; hop <= maxRedirects; hop++) {
      let url: URL;
      let addrs: ResolvedAddress[];
      let testPort: number | undefined;
      try {
        const route = testRoutes ? testRoutes[safeHostname(current)] : undefined;
        url = validateRequestUrl(current); // scheme/port/credentials/hostname checks always apply
        if (route) {
          addrs = [{ address: "127.0.0.1", family: 4 }];
          testPort = route.port;
        } else {
          addrs = await resolvePublicAddresses(url.hostname.replace(/\.$/, ""), resolver, dnsCache);
        }
      } catch (e) {
        if (e instanceof SsrfError) return fail(e.code, e.message, { blocked: true, detail: e.detail });
        return fail("dns_failed", "Phân giải DNS thất bại.");
      }
      record.resolved = addrs.map((a) => a.address);
      if (seen.has(url.href)) return fail("redirect_loop", "Phát hiện vòng lặp chuyển hướng.");
      seen.add(url.href);

      try {
        budget.take();
      } catch (e) {
        return fail((e as BudgetError).code, (e as Error).message);
      }

      const timeoutMs = Math.max(1, Math.min(opts.timeoutMs ?? 10_000, budget.remainingMs()));
      const base = { method, maxBytes, headers: opts.headers ?? {}, timeoutMs, testPort };
      let res: HopResult;
      try {
        try {
          res = await requestOnce(url, addrs, { ...base, rejectUnauthorized: true }, follow);
        } catch (e) {
          const code = (e as NodeJS.ErrnoException).code ?? "";
          if (opts.tolerateBadCert && url.protocol === "https:" && CERT_ERRORS.has(code)) {
            record.certError = { code, message: "Không xác minh được chứng chỉ TLS." };
            budget.take();
            res = await requestOnce(url, addrs, { ...base, rejectUnauthorized: false }, follow);
          } else throw e;
        }
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code ?? "ERR";
        record.durationMs = Date.now() - started;
        record.error = { code, message: friendlyNetError(code) };
        if (CERT_ERRORS.has(code)) record.certError = { code, message: friendlyNetError(code) };
        if (e instanceof BudgetError) record.error = { code: e.code, message: e.message };
        return record;
      }

      budget.addBytes(res.body.length);
      record.chain.push({ url: url.href, status: res.status, headers: res.headers });
      record.finalUrl = url.href;
      record.status = res.status;
      record.headers = res.headers;
      record.tls = res.tls ?? record.tls;

      const location = res.headers.location;
      if (follow && REDIRECT_STATUSES.has(res.status) && typeof location === "string") {
        if (hop === maxRedirects) return fail("too_many_redirects", `Chuyển hướng quá ${maxRedirects} lần.`);
        try {
          current = new URL(location, url).href;
        } catch {
          return fail("bad_redirect", "Đích chuyển hướng không phải URL hợp lệ.");
        }
        continue;
      }

      record.body = res.body.toString("utf8");
      record.bytes = res.body.length;
      record.truncated = res.truncated;
      record.contentType = String(res.headers["content-type"] ?? "").toLowerCase();
      record.durationMs = Date.now() - started;
      return record;
    }
    return fail("too_many_redirects", `Chuyển hướng quá ${maxRedirects} lần.`);
  };
}

export type SafeFetch = ReturnType<typeof createSafeFetcher>;

function friendlyNetError(code: string): string {
  switch (code) {
    case "ETIMEDOUT": return "Yêu cầu bị quá thời gian chờ.";
    case "ECONNREFUSED": return "Kết nối bị từ chối.";
    case "ECONNRESET": return "Kết nối bị ngắt đột ngột.";
    case "ENOTFOUND": return "Không tìm thấy tên miền.";
    case "EPROTO":
    case "ERR_SSL_WRONG_VERSION_NUMBER": return "Máy chủ không dùng TLS trên cổng này.";
    default:
      return CERT_ERRORS.has(code) ? "Không xác minh được chứng chỉ TLS." : "Yêu cầu thất bại.";
  }
}

function safeHostname(u: string): string {
  try {
    return new URL(u).hostname;
  } catch {
    return "";
  }
}
