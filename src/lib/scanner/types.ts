import type { FetchRecord, Headers } from "../ssrf/types";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = "high" | "medium" | "low";
/** pass = check ran and is fine · fail = problem found · info = informational note · unknown = could not be checked */
export type FindingStatus = "pass" | "fail" | "info" | "unknown";

export const CATEGORIES = [
  "Transport Security",
  "Headers",
  "Browser Security",
  "Cookies & Sessions",
  "Exposure",
  "Configuration",
  "Privacy",
] as const;
export type Category = (typeof CATEGORIES)[number];

export type Platform = "nextjs" | "vercel" | "cloudflare" | "nginx" | "apache" | "express";

export interface Snippet {
  platform: Platform | "generic";
  label: string;
  language: string;
  code: string;
}

export interface Remediation {
  /** One-sentence instruction. */
  summary: string;
  steps?: string[];
  /** Only emitted for platforms we positively detected (plus "generic" value references). Never guessed. */
  snippets: Snippet[];
  /** True when we could not identify the stack and are showing the header value only. */
  platformUnknown?: boolean;
}

export interface Reference {
  title: string;
  url: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  /** "What we found" — plain language. */
  summary: string;
  /** "Why it matters" — plain language. */
  explanation: string;
  /** Technical-mode detail. */
  technical?: string;
  /** Short, already-redacted evidence lines (headers, matched snippets with secrets masked). */
  evidence: string[];
  remediation: Remediation | null;
  affectedUrl: string | null;
  references: Reference[];
  /** Stable across scans of the same site; used for new/resolved diffing. */
  fingerprint: string;
}

export interface Rule {
  id: string;
  title: string;
  category: Category;
  /** Pure function of the observations: no I/O, deterministic. */
  run(obs: Observations): Finding[];
}

// ------------------------------------------------------------------ observations

export interface ScriptRef {
  url: string | null; // null for inline
  inline: boolean;
  sameOrigin: boolean;
  integrity?: string;
  crossorigin?: string;
  /** Inline content or fetched body (capped). In memory only. */
  content?: string;
  fetched?: FetchRecord;
}

export interface ResourceRef {
  tag: string;
  attr: string;
  url: string; // absolute
}

export interface FormRef {
  action: string; // absolute
  method: string;
  hasPassword: boolean;
}

export interface ParsedHtml {
  title: string;
  scripts: ScriptRef[];
  stylesheets: { href: string; integrity?: string; sameOrigin: boolean }[];
  resources: ResourceRef[]; // every src/href-ish reference we care about for mixed content
  forms: FormRef[];
  hasPasswordInput: boolean;
  metaCsp: string | null;
  metaRefresh: string | null;
  generator: string | null;
  metaReferrer: string | null;
  metaCharset: string | null;
  anchors: string[]; // absolute same-origin anchors (capped)
}

export interface FileProbe {
  url: string;
  /** True only when the file really exists (200 and a plausible content type/body, not an SPA fallback). */
  present: boolean;
  status: number | null;
  contentType: string;
  body: string; // capped
  error?: string;
}

export interface SourceMapProbe {
  scriptUrl: string;
  mapUrl: string;
  exposed: boolean;
  status: number | null;
}

export interface CorsProbe {
  testedOrigin: string;
  status: number | null;
  acao: string | null;
  acac: string | null;
  vary: string | null;
}

/** Kết quả OPTIONS tới trang chủ: chỉ đọc header Allow, không thực thi phương thức nào. */
export interface MethodsProbe { status: number | null; allow: string | null }

export interface DnsInfo {
  caa: string[] | null;
  spf: string | null | undefined; // undefined = lookup failed
  dmarc: string | null | undefined;
  domain: string | null;
  /** Số bản ghi SPF tìm thấy (nhiều hơn 1 là lỗi cấu hình). */
  spfRecords?: number;
  /** CNAME của chính hostname được quét (null = không có CNAME). */
  cname?: string[] | null;
  mx?: string[] | null;
  ns?: string[] | null;
  /** true khi bộ phân giải xác thực DNSSEC (cờ AD); undefined = không tra được. */
  dnssec?: boolean | null;
  mtaSts?: boolean | null;
}

export interface Observations {
  target: { input: string; url: string; origin: string; host: string; scheme: "http" | "https" };
  /** GET https://host/ (null if never attempted) */
  https: FetchRecord | null;
  /** GET http://host/ following redirects */
  http: FetchRecord | null;
  /** The record used for page analysis: https if it worked, else http. */
  page: FetchRecord | null;
  pageIsHttps: boolean;
  html: ParsedHtml | null;
  scripts: ScriptRef[];
  sourceMaps: SourceMapProbe[];
  files: { robots: FileProbe | null; sitemap: FileProbe | null; securityTxt: FileProbe | null };
  cors: CorsProbe | null;
  /** Phản hồi của một đường dẫn chắc chắn không tồn tại (để xem trang lỗi có lộ thông tin không). */
  notFound: FetchRecord | null;
  /** Phiên bản www / không-www của hostname (nếu có). */
  altHost: { host: string; record: FetchRecord | null } | null;
  /** A login/account/admin-looking same-origin page, if one was discovered. */
  sensitivePage: FetchRecord | null;
  methods: MethodsProbe | null;
  dns: DnsInfo | null;
  legacyTls: { tls10: boolean | null; tls11: boolean | null; h2?: boolean | null } | null;
  platforms: Platform[];
  technologies: string[];
  limits: { requestsUsed: number; hitLimit: string | null };
  scannedAt: string;
}

export type { Headers };
