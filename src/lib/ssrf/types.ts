/** Pure types shared by the scanner (container) and the Worker bundle. */

export type Headers = Record<string, string | string[]>;

export interface HttpHop {
  url: string;
  status: number;
  headers: Headers;
}

export interface TlsInfo {
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authError?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  issuer?: string;
  subject?: string;
  altNames?: string[];
  /** Khoá công khai của chứng chỉ lá. */
  keyType?: string;
  keyBits?: number;
  curve?: string;
  validityDays?: number;
  selfSigned?: boolean;
  wildcard?: boolean;
  chainLength?: number;
}

export interface FetchRecord {
  requestedUrl: string;
  finalUrl: string;
  status: number | null;
  headers: Headers;
  chain: HttpHop[];
  /** Body text, capped at maxBytes. Held in memory for analysis only; never persisted. */
  body: string;
  bytes: number;
  truncated: boolean;
  contentType: string;
  tls?: TlsInfo;
  resolved: string[];
  durationMs: number;
  /** Set when the TLS certificate failed verification (the page was then fetched unverified, if allowed). */
  certError?: { code: string; message: string };
  /** Set if the request (or a redirect hop) failed or was refused. */
  error?: { code: string; message: string; blocked?: boolean; detail?: string };
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

/** Hàm tải an toàn: có hai bản cài đặt (Node + ghim IP trong container; fetch của Worker + kiểm tra DNS-over-HTTPS). */
export type SafeFetch = (rawUrl: string, opts?: FetchOptions) => Promise<FetchRecord>;
