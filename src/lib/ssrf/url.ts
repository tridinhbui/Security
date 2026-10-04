import { classifyLiteral } from "./ip";

export class SsrfError extends Error {
  constructor(
    public readonly code:
      | "invalid_url"
      | "scheme_not_allowed"
      | "credentials_not_allowed"
      | "port_not_allowed"
      | "internal_hostname"
      | "non_public_ip"
      | "dns_failed"
      | "dns_mixed_answers"
      | "too_many_redirects"
      | "bad_redirect",
    message: string,
    public readonly detail?: string,
  ) {
    super(message);
    this.name = "SsrfError";
  }
}

export const ALLOWED_PORTS: ReadonlySet<number> = new Set([80, 443]);
const MAX_URL_LENGTH = 2048;

/** Suffixes / names that denote internal namespaces, whatever they resolve to. */
const INTERNAL_SUFFIXES = [
  ".localhost", ".local", ".internal", ".intranet", ".lan", ".corp", ".home", ".private",
  ".localdomain", ".home.arpa", ".in-addr.arpa", ".ip6.arpa", ".test", ".invalid", ".example",
];
const INTERNAL_NAMES = new Set([
  "localhost", "metadata", "metadata.google.internal", "instance-data", "kubernetes", "kubernetes.default",
]);

export interface NormalizedTarget {
  /** Canonical URL: scheme://host[:port]/path — no credentials, query, or fragment. */
  url: string;
  origin: string;
  scheme: "http" | "https";
  /** Lower-case, IDN → punycode, no trailing dot. */
  host: string;
  port: number;
  path: string;
}

export function assertPublicHostname(host: string): void {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h) throw new SsrfError("invalid_url", "URL không có tên miền.");
  // IP literals in any encoding (dotted, decimal, hex, octal, IPv6) are classified numerically.
  // Public literals are allowed; they are re-validated on every redirect hop.
  const literal = classifyLiteral(h);
  if (literal) {
    if (!literal.public) throw new SsrfError("non_public_ip", "Địa chỉ này không thể truy cập công khai.", literal.reason);
    return;
  }
  if (INTERNAL_NAMES.has(h) || INTERNAL_SUFFIXES.some((s) => h.endsWith(s))) {
    throw new SsrfError("internal_hostname", "Không thể quét tên miền nội bộ.", h);
  }
  if (!h.includes(".")) throw new SsrfError("internal_hostname", "Hãy nhập tên miền đầy đủ, ví dụ example.com.", h);
  if (h.length > 253 || h.split(".").some((l) => l.length === 0 || l.length > 63)) {
    throw new SsrfError("invalid_url", "Tên miền này không hợp lệ.");
  }
}

/**
 * Parse, validate and normalise a user-supplied target. Pure and synchronous: DNS is
 * resolved separately (see dns.ts) and re-validated on every redirect hop.
 */
export function normalizeTargetUrl(input: string): NormalizedTarget {
  const raw = input.trim();
  if (!raw || raw.length > MAX_URL_LENGTH) throw new SsrfError("invalid_url", "Hãy nhập địa chỉ website hợp lệ.");
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) throw new SsrfError("invalid_url", "URL chứa ký tự không hợp lệ.");

  // A scheme is explicit only when followed by "://". This makes "localhost:3000" and
  // "javascript:alert(1)" fall through to the https:// branch, where they fail validation.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  let u: URL;
  try {
    u = new URL(hasScheme ? raw : `https://${raw}`);
  } catch {
    throw new SsrfError("invalid_url", "Đây không phải là URL hợp lệ.");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SsrfError("scheme_not_allowed", "Chỉ có thể quét URL http và https.", u.protocol);
  }
  if (u.username || u.password) {
    throw new SsrfError("credentials_not_allowed", "Không cho phép URL có chứa thông tin đăng nhập.");
  }
  const scheme = u.protocol === "https:" ? "https" : "http";
  const port = u.port ? Number(u.port) : scheme === "https" ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) {
    throw new SsrfError("port_not_allowed", "Chỉ có thể quét các cổng tiêu chuẩn 80 và 443.", String(port));
  }
  // WHATWG parsing has already canonicalised decimal/hex/octal IPv4 and compressed IPv6.
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  assertPublicHostname(host);

  const path = u.pathname || "/";
  const defaultPort = scheme === "https" ? 443 : 80;
  const origin = `${scheme}://${host}${port === defaultPort ? "" : `:${port}`}`;
  return { url: origin + path, origin, scheme, host, port, path };
}

/** Validate a redirect/absolute URL string found in a Location header. Query strings are kept. */
export function validateRequestUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SsrfError("bad_redirect", "Đích chuyển hướng không hợp lệ.");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new SsrfError("scheme_not_allowed", "Chỉ có thể quét URL http và https.", u.protocol);
  }
  if (u.username || u.password) throw new SsrfError("credentials_not_allowed", "Không cho phép thông tin đăng nhập trong URL.");
  const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  if (!ALLOWED_PORTS.has(port)) throw new SsrfError("port_not_allowed", "Cổng không được phép.", String(port));
  assertPublicHostname(u.hostname.toLowerCase().replace(/\.$/, ""));
  return u;
}
