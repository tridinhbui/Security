import type { FetchRecord, Headers } from "@/lib/ssrf/fetch";
import { fingerprint } from "../fingerprint";
import { parseHtml } from "../parse";
import { ALL_RULES } from "../rules";
import type { FileProbe, Finding, Observations } from "../types";

export const HOME = "https://example.com/";

export const GOOD_HEADERS: Headers = {
  "content-type": "text/html; charset=utf-8",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

export const GOOD_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>Example</title><script src="/app.js"></script><link rel="stylesheet" href="/s.css"></head>
<body><h1>Hi</h1><a href="/about">About</a><img src="/logo.png"></body></html>`;

export function rec(over: Partial<FetchRecord> = {}): FetchRecord {
  const headers = over.headers ?? { ...GOOD_HEADERS };
  const url = over.finalUrl ?? over.requestedUrl ?? HOME;
  return {
    requestedUrl: url, finalUrl: url, status: 200, headers, chain: [{ url, status: 200, headers }], body: GOOD_HTML, bytes: GOOD_HTML.length,
    truncated: false, contentType: String(headers["content-type"] ?? "text/html"), resolved: ["93.184.216.34"], durationMs: 50,
    tls: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", authorized: true, validTo: "Jan 1 2030", daysRemaining: 90, issuer: "Let's Encrypt", subject: "example.com", keyType: "rsa", keyBits: 2048, validityDays: 90, chainLength: 3, wildcard: false },
    ...over,
  };
}

const file = (url: string, body: string, contentType: string): FileProbe => ({ url, present: true, status: 200, contentType, body });

/** A fully hardened site: every rule should pass or stay silent. */
export function baseline(): Observations {
  const https = rec();
  const http = rec({
    requestedUrl: "http://example.com/", finalUrl: HOME,
    chain: [{ url: "http://example.com/", status: 301, headers: { location: HOME } }, { url: HOME, status: 200, headers: https.headers }],
    headers: https.headers,
  });
  const html = parseHtml(GOOD_HTML, HOME);
  const fp = fingerprint(https.headers, GOOD_HTML, html);
  return {
    target: { input: "example.com", url: HOME, origin: "https://example.com", host: "example.com", scheme: "https" },
    https, http, page: https, pageIsHttps: true, html, scripts: html.scripts, sourceMaps: [],
    files: {
      robots: file("https://example.com/robots.txt", "User-agent: *\nDisallow: /cart\n", "text/plain"),
      sitemap: file("https://example.com/sitemap.xml", "<urlset></urlset>", "application/xml"),
      securityTxt: file("https://example.com/.well-known/security.txt", "Contact: mailto:sec@example.com\nExpires: 2099-01-01T00:00:00Z\n", "text/plain"),
    },
    cors: { testedOrigin: "https://vibesec-cors-probe.invalid", status: 200, acao: null, acac: null, vary: null },
    notFound: rec({ requestedUrl: "https://example.com/vibesec-khong-ton-tai-x", finalUrl: "https://example.com/vibesec-khong-ton-tai-x", status: 404, body: "<html><h1>404</h1></html>" }),
    altHost: { host: "www.example.com", record: rec({ requestedUrl: "https://www.example.com/", finalUrl: "https://www.example.com/", status: 301 }) },
    sensitivePage: null,
    dns: { domain: "example.com", caa: ['0 issue "letsencrypt.org"'], spf: "v=spf1 include:_spf.example.net -all", spfRecords: 1, dmarc: "v=DMARC1; p=reject; rua=mailto:d@example.com", cname: null, mx: ["mx.example.com"], ns: ["ns1.example.com"], dnssec: true, mtaSts: true },
    legacyTls: { tls10: false, tls11: false, h2: true },
    platforms: fp.platforms, technologies: fp.technologies,
    limits: { requestsUsed: 6, hitLimit: null }, scannedAt: new Date().toISOString(),
  };
}

export function run(obs: Observations, ruleId?: string): Finding[] {
  return ALL_RULES.filter((r) => !ruleId || r.id === ruleId).flatMap((r) => r.run(obs));
}
export const failing = (obs: Observations, ruleId?: string) => run(obs, ruleId).filter((f) => f.status === "fail");
export const hdr = (o: Observations) => o.https!.headers;
/** Replace page body/html everywhere consistently. */
export function setHtml(o: Observations, html: string) {
  o.https!.body = html;
  o.html = parseHtml(html, o.https!.finalUrl);
  o.scripts = o.html.scripts;
}
