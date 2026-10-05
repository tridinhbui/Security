import { BudgetError, type ScanBudget } from "./budget";
import { resolvePublicAddresses, type ResolvedAddress, type Resolver } from "./dns";
import type { FetchOptions, FetchRecord, Headers, SafeFetch } from "./types";
import { SsrfError, validateRequestUrl } from "./url";

/**
 * Bộ tải an toàn cho CLOUDFLARE WORKER (không cần container, nên gần như miễn phí).
 *
 * Khác bản container (src/lib/ssrf/fetch.ts) ở đúng một điểm: Worker không ghim được IP kết nối, vì fetch() tự phân giải DNS.
 * Các lớp bảo vệ còn lại và lý do chấp nhận được:
 *  - Mọi bước (kể cả mỗi lần chuyển hướng) đều được kiểm tra lại: scheme, cổng, thông tin đăng nhập, tên miền nội bộ, IP literal.
 *  - Mọi bước đều phân giải DNS qua DoH và yêu cầu TẤT CẢ câu trả lời là IP công khai (từ chối nếu lẫn IP nội bộ).
 *  - Hạ tầng Cloudflare KHÔNG định tuyến được tới dải IP riêng/loopback; fetch() của Worker từ chối IP literal và tên miền trỏ vào dải bị cấm.
 *    Vì vậy cửa sổ DNS-rebinding không dẫn tới mạng nội bộ nào để chạm tới.
 *  - Không tự theo chuyển hướng (redirect: "manual"); không giải nén (accept-encoding: identity); giới hạn byte/thời gian/request.
 * Không hỗ trợ tolerateBadCert: chứng chỉ hỏng làm fetch thất bại → bên gọi chuyển sang đường container (xem hybrid-scanner).
 */
export const USER_AGENT = "VibeSecBot/1.0 (+https://vibesec.app/bot; passive, non-destructive security audit)";
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export interface WorkerFetcherDeps {
  resolver: Resolver;
  dnsCache?: Map<string, { at: number; addrs: ResolvedAddress[] }>;
  fetchImpl?: typeof fetch;
  /** Hostname của chính ứng dụng này: không cho tự quét (tránh vòng lặp và tự gây tải). */
  denyHosts?: string[];
}

async function readCapped(res: Response, maxBytes: number): Promise<{ text: string; bytes: number; truncated: boolean }> {
  if (!res.body) return { text: "", bytes: 0, truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0, truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > maxBytes) {
      const keep = value.length - (size - maxBytes);
      if (keep > 0) chunks.push(value.subarray(0, keep));
      size = maxBytes;
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.length; }
  return { text: new TextDecoder("utf-8").decode(buf), bytes: size, truncated };
}

function headersOf(res: Response): Headers {
  const h: Headers = {};
  res.headers.forEach((v, k) => { if (k !== "set-cookie") h[k.toLowerCase()] = v; });
  const cookies = res.headers.getSetCookie?.() ?? [];
  if (cookies.length) h["set-cookie"] = cookies;
  return h;
}

export function createWorkerFetcher(budget: ScanBudget, deps: WorkerFetcherDeps): SafeFetch {
  const doFetch = deps.fetchImpl ?? fetch;
  const deny = (deps.denyHosts ?? []).map((h) => h.toLowerCase());

  return async function workerFetch(rawUrl: string, opts: FetchOptions = {}): Promise<FetchRecord> {
    const started = Date.now();
    const maxBytes = opts.maxBytes ?? 1024 * 1024;
    const maxRedirects = opts.maxRedirects ?? 5;
    const follow = opts.followRedirects ?? true;
    const method = opts.method ?? "GET";
    const record: FetchRecord = { requestedUrl: rawUrl, finalUrl: rawUrl, status: null, headers: {}, chain: [], body: "", bytes: 0, truncated: false, contentType: "", resolved: [], durationMs: 0 };
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
      try {
        url = validateRequestUrl(current);
        const host = url.hostname.toLowerCase().replace(/\.$/, "");
        if (deny.some((d) => host === d || host.endsWith(`.${d}`))) throw new SsrfError("internal_hostname", "Không thể tự quét chính hệ thống này.");
        addrs = await resolvePublicAddresses(host, deps.resolver, deps.dnsCache);
      } catch (e) {
        if (e instanceof SsrfError) return fail(e.code, e.message, { blocked: true, detail: e.detail });
        return fail("dns_failed", "Phân giải DNS thất bại.");
      }
      record.resolved = addrs.map((a) => a.address);
      if (seen.has(url.href)) return fail("redirect_loop", "Phát hiện vòng lặp chuyển hướng.");
      seen.add(url.href);

      try { budget.take(); } catch (e) { return fail((e as BudgetError).code, (e as Error).message); }

      const timeoutMs = Math.max(1, Math.min(opts.timeoutMs ?? 10_000, budget.remainingMs()));
      let res: Response;
      try {
        res = await doFetch(url.href, {
          method,
          redirect: "manual",
          signal: AbortSignal.timeout(timeoutMs),
          headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5", "accept-encoding": "identity", ...opts.headers },
        });
      } catch (e) {
        const timedOut = (e as Error).name === "TimeoutError" || (e as Error).name === "AbortError";
        return fail(timedOut ? "ETIMEDOUT" : "FETCH_FAILED", timedOut ? "Yêu cầu bị quá thời gian chờ." : "Yêu cầu thất bại.");
      }

      const headers = headersOf(res);
      record.chain.push({ url: url.href, status: res.status, headers });
      record.finalUrl = url.href;
      record.status = res.status;
      record.headers = headers;

      const location = headers.location;
      const isRedirect = REDIRECT_STATUSES.has(res.status) && typeof location === "string";
      if (follow && isRedirect) {
        await res.body?.cancel().catch(() => undefined);
        if (hop === maxRedirects) return fail("too_many_redirects", `Chuyển hướng quá ${maxRedirects} lần.`);
        try { current = new URL(location, url).href; } catch { return fail("bad_redirect", "Đích chuyển hướng không phải URL hợp lệ."); }
        continue;
      }

      if (method === "HEAD" || (isRedirect && !follow)) await res.body?.cancel().catch(() => undefined);
      else {
        try {
          const r = await readCapped(res, maxBytes);
          record.body = r.text; record.bytes = r.bytes; record.truncated = r.truncated;
          budget.addBytes(r.bytes);
        } catch {
          return fail("FETCH_FAILED", "Đọc phản hồi thất bại.");
        }
      }
      record.contentType = String(headers["content-type"] ?? "").toLowerCase();
      record.durationMs = Date.now() - started;
      return record;
    }
    return fail("too_many_redirects", `Chuyển hướng quá ${maxRedirects} lần.`);
  };
}
