import type { ReportData } from "@/components/Report";
import { compareScans } from "./compare";
import type { FetchRecord, Headers } from "./ssrf/fetch";
import { evaluate } from "./scanner/evaluate";
import { fingerprint } from "./scanner/fingerprint";
import { parseHtml } from "./scanner/parse";
import { calculateScore, prioritize, SCORE_DISCLAIMER } from "./scanner/score";
import type { Observations } from "./scanner/types";

/**
 * Demo mode. We do NOT hand-write findings: a synthetic site is fed through the real rule engine,
 * so the demo always reflects what the scanner genuinely produces.
 */
const HOST = "demo-shop.example.com";
const HOME = `https://${HOST}/`;

function build(variant: "before" | "after"): Observations {
  // "after" = partially fixed: transport/cookie/secret issues resolved, CSP/source-maps/mixed-content still open.
  const fixed = variant === "after";
  const headers: Headers = {
    "content-type": "text/html; charset=utf-8",
    server: "Vercel",
    "x-vercel-id": "fra1::abc-1699999999999-0123456789ab",
    "x-powered-by": fixed ? "" : "Next.js",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "set-cookie": fixed ? "session=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax" : "session=<redacted>; Path=/",
    ...(fixed ? { "strict-transport-security": "max-age=63072000; includeSubDomains", "x-frame-options": "DENY" } : { "strict-transport-security": "max-age=300" }),
  };
  if (fixed) delete headers["x-powered-by"];
  const body = `<!doctype html><html><head><meta charset="utf-8"><title>Cửa hàng demo</title><script src="/_next/static/chunks/main-app.js"></script>
    <script src="https://www.googletagmanager.com/gtag/js?id=G-DEMO"></script></head><body>
    <a href="/login">Tài khoản</a><img src="http://${HOST}/hero.png"><script src="https://cdn.jsdelivr.net/npm/jquery@${fixed ? "3.7.1" : "3.4.1"}/dist/jquery.min.js"></script>
    ${fixed ? "" : `<script>fbq('init','123');</script>`}</body></html>`;
  const html = parseHtml(body, HOME);
  const fp = fingerprint(headers, body, html);
  const rec: FetchRecord = {
    requestedUrl: HOME, finalUrl: HOME, status: 200, headers, chain: [{ url: HOME, status: 200, headers }], body, bytes: body.length,
    truncated: false, contentType: "text/html", resolved: ["76.76.21.21"], durationMs: 120,
    tls: { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", authorized: true, validTo: "Mar 1 2027", daysRemaining: 120, issuer: "Let's Encrypt", subject: HOST, keyType: "rsa", keyBits: 2048, validityDays: 90, chainLength: 3 },
  };
  const http: FetchRecord = { ...rec, requestedUrl: `http://${HOST}/`, chain: [{ url: `http://${HOST}/`, status: 308, headers: { location: HOME } }, { url: HOME, status: 200, headers }] };
  const file = (path: string, text: string, ct: string) => ({ url: `https://${HOST}${path}`, present: true, status: 200, contentType: ct, body: text });
  return {
    target: { input: HOST, url: HOME, origin: `https://${HOST}`, host: HOST, scheme: "https" },
    https: rec, http, page: rec, pageIsHttps: true, html,
    scripts: [{ url: `https://${HOST}/_next/static/chunks/main-app.js`, inline: false, sameOrigin: true, content: fixed ? "console.log('app')" : `const stripe="sk_test_${"4eC39HqLyjWDarjtT1zdp7dc"}";` }],
    sourceMaps: [{ scriptUrl: `https://${HOST}/_next/static/chunks/main-app.js`, mapUrl: `https://${HOST}/_next/static/chunks/main-app.js.map`, exposed: true, status: 200 }],
    files: {
      robots: file("/robots.txt", "User-agent: *\nDisallow: /cart\n", "text/plain"),
      sitemap: file("/sitemap.xml", "<urlset></urlset>", "application/xml"),
      securityTxt: { url: `https://${HOST}/.well-known/security.txt`, present: false, status: 404, contentType: "", body: "" },
    },
    notFound: {
      ...rec, requestedUrl: `https://${HOST}/vibesec-khong-ton-tai-demo`, finalUrl: `https://${HOST}/vibesec-khong-ton-tai-demo`, status: 404,
      body: fixed ? "<html><h1>404 – Không tìm thấy trang</h1></html>" : "<b>Warning</b>: Undefined variable $user in /var/www/html/app/index.php on line 12",
      chain: [{ url: `https://${HOST}/vibesec-khong-ton-tai-demo`, status: 404, headers: {} }],
    },
    altHost: { host: `www.${HOST}`, record: { ...rec, requestedUrl: `https://www.${HOST}/`, finalUrl: `https://www.${HOST}/`, status: 301, chain: [{ url: `https://www.${HOST}/`, status: 301, headers: { location: HOME } }] } },
    cors: { testedOrigin: "https://vibesec-cors-probe.invalid", status: 200, acao: fixed ? null : "https://vibesec-cors-probe.invalid", acac: null, vary: null },
    sensitivePage: null,
    dns: { domain: "example.com", caa: [], spf: fixed ? "v=spf1 include:_spf.example.net -all" : "v=spf1 include:_spf.example.net +all", spfRecords: 1, dmarc: fixed ? "v=DMARC1; p=quarantine; rua=mailto:d@example.com" : null, cname: null, mx: ["mx.example.net"], dnssec: false, mtaSts: false },
    legacyTls: { tls10: false, tls11: fixed ? false : true, h2: true },
    platforms: fp.platforms, technologies: fp.technologies,
    limits: { requestsUsed: 21, hitLimit: null }, scannedAt: fixed ? "2026-10-02T09:14:00.000Z" : "2026-09-25T09:10:00.000Z",
  };
}

export function demoReport(): ReportData {
  const now = evaluate(build("after"));
  const before = evaluate(build("before"));
  const nowFindings = prioritize(now.findings);
  const prevFindings = prioritize(before.findings);
  const s1 = calculateScore(nowFindings);
  const s0 = calculateScore(prevFindings);
  const c = compareScans({ score: s0.score, findings: prevFindings }, { score: s1.score, findings: nowFindings });
  return {
    url: HOME, host: HOST, scannedAt: "2026-10-02T09:14:00.000Z", score: s1.score, grade: s1.grade, categoryScores: s1.categoryScores,
    severityCounts: s1.severityCounts, platforms: ["nextjs", "vercel"], requestCount: 21, findings: nowFindings, targets: [],
    comparison: { previousScore: s0.score, previousAt: "2026-09-25T09:10:00.000Z", scoreDelta: c.scoreDelta, newFindings: c.newFindings, resolvedFindings: c.resolvedFindings, unchanged: c.unchanged },
    variant: "demo", disclaimer: SCORE_DISCLAIMER,
  };
}

/** The "before" state, used on the landing page to show a realistic example with real issues. */
export function demoBeforeReport(): ReportData {
  const r = evaluate(build("before"));
  const findings = prioritize(r.findings);
  const s = calculateScore(findings);
  return { url: HOME, host: HOST, scannedAt: "2026-09-25T09:10:00.000Z", score: s.score, grade: s.grade, categoryScores: s.categoryScores, severityCounts: s.severityCounts, platforms: ["nextjs", "vercel"], requestCount: 21, findings, variant: "demo", disclaimer: SCORE_DISCLAIMER };
}
