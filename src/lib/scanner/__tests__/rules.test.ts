import { describe, expect, it } from "vitest";
import { ALL_RULES } from "../rules";
import { parseCsp } from "../rules/headers";
import { parseSetCookie } from "../rules/cookies";
import { baseline, failing, GOOD_HEADERS, hdr, HOME, rec, run, setHtml } from "./fixtures";

describe("rule registry", () => {
  it("has unique ids and complete metadata on every result", () => {
    const o = baseline();
    for (const f of run(o)) {
      expect(f.ruleId).toBeTruthy();
      expect(f.title && f.category && f.summary && f.explanation).toBeTruthy();
      expect(["critical", "high", "medium", "low", "info"]).toContain(f.severity);
      expect(["high", "medium", "low"]).toContain(f.confidence);
      expect(["pass", "fail", "info", "unknown"]).toContain(f.status);
      expect(Array.isArray(f.evidence) && Array.isArray(f.references)).toBe(true);
      expect(f.fingerprint.startsWith(f.ruleId)).toBe(true);
    }
    expect(new Set(ALL_RULES.map((r) => r.id)).size).toBe(ALL_RULES.length);
  });
  it("baseline hardened site: no failing findings from any rule", () => {
    expect(failing(baseline()).map((f) => `${f.ruleId}: ${f.title}`)).toEqual([]);
  });
  it("every rule that can fail ships remediation; with an unknown platform the choices are explicit labelled alternatives, never a silent guess", () => {
    const o = baseline();
    delete hdr(o)["content-security-policy"];
    for (const f of failing(o)) {
      expect(f.remediation).toBeTruthy();
      // nền tảng chưa rõ → cờ platformUnknown + mọi snippet theo nền tảng đều có nhãn "Nginx / Apache / …" để người dùng tự chọn
      if (f.remediation!.platformUnknown) expect(f.remediation!.snippets.every((s) => s.label.length > 3)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------- transport
describe("tls.https-available", () => {
  const id = "tls.https-available";
  it("fails High when port 443 refuses", () => {
    const o = baseline();
    o.https = rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } });
    expect(failing(o, id)[0]).toMatchObject({ severity: "high", confidence: "high" });
  });
  it.each([["CERT_HAS_EXPIRED", "hết hạn"], ["DEPTH_ZERO_SELF_SIGNED_CERT", "tự ký"], ["ERR_TLS_CERT_ALTNAME_INVALID", "không khớp"]])("untrusted cert %s", (code, text) => {
    const o = baseline();
    o.https!.certError = { code, message: "x" };
    const f = failing(o, id)[0]!;
    expect(f.severity).toBe("high");
    expect(f.summary).toContain(text);
  });
  it("is 'unknown' (not a failure) on timeouts", () => {
    const o = baseline();
    o.https = rec({ status: null, error: { code: "ETIMEDOUT", message: "x" } });
    expect(failing(o, id)).toHaveLength(0);
    expect(run(o, id)[0]!.status).toBe("unknown");
  });
  it("passes on a healthy site; silent if not attempted", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); o.https = null;
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("tls.certificate-expiry", () => {
  const id = "tls.certificate-expiry";
  it.each([[5, "medium"], [20, "low"]])("%i days → %s", (days, sev) => {
    const o = baseline(); o.https!.tls!.daysRemaining = days;
    expect(failing(o, id)[0]!.severity).toBe(sev);
  });
  it("passes at 90 days and ignores already-expired (covered by https-available)", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); o.https!.tls!.daysRemaining = -3;
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("tls.protocol-version", () => {
  const id = "tls.protocol-version";
  it("fails Medium if TLS 1.0 or 1.1 handshakes succeed", () => {
    const o = baseline(); o.legacyTls = { tls10: true, tls11: false };
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
    o.legacyTls = { tls10: false, tls11: true };
    expect(failing(o, id)[0]!.summary).toContain("TLS 1.1");
  });
  it("probe errors/unknown never produce a failure", () => {
    const o = baseline(); o.legacyTls = { tls10: null, tls11: null };
    expect(failing(o, id)).toHaveLength(0);
  });
  it("passes on TLS 1.3", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

describe("tls.http-to-https-redirect", () => {
  const id = "tls.http-to-https-redirect";
  it("fails Medium when HTTP is served without redirect but HTTPS works", () => {
    const o = baseline();
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/" });
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });
  it("no finding if HTTPS itself is broken (reported elsewhere)", () => {
    const o = baseline();
    o.https = rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } });
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/" });
    expect(failing(o, id)).toHaveLength(0);
  });
  it("closed port 80 is informational", () => {
    const o = baseline();
    o.http = rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } });
    expect(run(o, id)[0]).toMatchObject({ status: "info" });
  });
  it("passes on redirect", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("includes Nginx redirect snippet only when Nginx detected", () => {
    const o = baseline();
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/" });
    o.platforms = ["nginx"];
    const snip = failing(o, id)[0]!.remediation!.snippets;
    expect(snip.map((s) => s.platform)).toEqual(["nginx"]);
    expect(snip[0]!.code).toContain("return 301 https://");
  });
});

describe("tls.hsts", () => {
  const id = "tls.hsts";
  it("missing → Medium", () => {
    const o = baseline(); delete hdr(o)["strict-transport-security"];
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
  });
  it("short lifetime → Low", () => {
    const o = baseline(); hdr(o)["strict-transport-security"] = "max-age=3600";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("max-age=0 is handled by headers.broken, not here", () => {
    const o = baseline(); hdr(o)["strict-transport-security"] = "max-age=0";
    expect(failing(o, id)).toHaveLength(0);
    expect(failing(o, "headers.broken").some((f) => f.fingerprint.endsWith("|hsts-zero"))).toBe(true);
  });
  it("skipped when HTTPS unavailable", () => {
    const o = baseline(); o.https = rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } });
    expect(run(o, id)).toHaveLength(0);
  });
  it("passes", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

describe("tls.insecure-login-form", () => {
  const id = "tls.insecure-login-form";
  it("password form posting to http:// → Critical", () => {
    const o = baseline();
    setHtml(o, `<form action="http://example.com/login" method="post"><input type="password"></form>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "critical", confidence: "high" });
  });
  it("password form with GET → High", () => {
    const o = baseline();
    setHtml(o, `<form action="/login" method="get"><input type="password"></form>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "high" });
  });
  it("password input on an HTTP page → High", () => {
    const o = baseline();
    o.pageIsHttps = false;
    setHtml(o, `<form action="/login" method="post"><input type="password"></form>`);
    expect(failing(o, id).map((f) => f.severity)).toContain("high");
  });
  it("secure form passes; no form is silent", () => {
    const o = baseline();
    setHtml(o, `<form action="/login" method="post"><input type="password"></form>`);
    expect(run(o, id)[0]!.status).toBe("pass");
    expect(run(baseline(), id)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------- headers
describe("headers.csp", () => {
  const id = "headers.csp";
  it("missing → Medium", () => {
    const o = baseline(); delete hdr(o)["content-security-policy"];
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });
  it("report-only → Low", () => {
    const o = baseline(); delete hdr(o)["content-security-policy"]; hdr(o)["content-security-policy-report-only"] = "default-src 'self'";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("unsafe-inline without nonce → Medium; with nonce passes", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'";
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
    hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'; base-uri 'self'";
    expect(failing(o, id)).toHaveLength(0);
  });
  it("falls back to default-src; wildcard script source → Medium", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "default-src *";
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
  });
  it("unsafe-eval alone → Low", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("never High/Critical", () => {
    const o = baseline(); hdr(o)["content-security-policy"] = "script-src * 'unsafe-inline' 'unsafe-eval'";
    expect(failing(o, id).every((f) => !["high", "critical"].includes(f.severity))).toBe(true);
  });
  it("parseCsp: first directive occurrence wins", () => {
    expect(parseCsp("script-src 'self'; script-src *").directives.get("script-src")).toEqual(["'self'"]);
  });
  it("emits Next.js snippet when Next.js is detected", () => {
    const o = baseline(); delete hdr(o)["content-security-policy"]; o.platforms = ["nextjs", "vercel"];
    const platforms = failing(o, id)[0]!.remediation!.snippets.map((s) => s.platform);
    expect(platforms).toEqual(["nextjs", "vercel"]);
  });
  it("passes on a strict policy; skips non-HTML", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); o.https!.contentType = "application/json";
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("headers.frame-protection", () => {
  const id = "headers.frame-protection";
  it("neither header → Low", () => {
    const o = baseline(); delete hdr(o)["x-frame-options"]; hdr(o)["content-security-policy"] = "default-src 'self'";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("Medium (confidence medium) on pages with a password field", () => {
    const o = baseline(); delete hdr(o)["x-frame-options"]; hdr(o)["content-security-policy"] = "default-src 'self'";
    setHtml(o, `<form method="post"><input type="password"></form>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "medium" });
  });
  it("frame-ancestors alone or XFO SAMEORIGIN passes", () => {
    const o = baseline(); delete hdr(o)["x-frame-options"];
    expect(run(o, id)[0]!.status).toBe("pass");
    const p = baseline(); hdr(p)["x-frame-options"] = "sameorigin"; hdr(p)["content-security-policy"] = "default-src 'self'";
    expect(run(p, id)[0]!.status).toBe("pass");
  });
});

describe("headers.x-content-type-options", () => {
  const id = "headers.x-content-type-options";
  it("missing → Low", () => {
    const o = baseline(); delete hdr(o)["x-content-type-options"];
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("wrong value handled by headers.broken", () => {
    const o = baseline(); hdr(o)["x-content-type-options"] = "nosniff, nosniff2";
    expect(failing(o, id)).toHaveLength(0);
    expect(failing(o, "headers.broken")).toHaveLength(1);
  });
  it("passes (case-insensitive)", () => {
    const o = baseline(); hdr(o)["x-content-type-options"] = " NoSniff ";
    expect(run(o, id)[0]!.status).toBe("pass");
  });
});

describe("headers.broken", () => {
  const id = "headers.broken";
  /** Khoá ổn định của từng phát hiện (không phụ thuộc ngôn ngữ hiển thị). */
  const titleFor = (mut: (h: Record<string, string | string[]>) => void) => {
    const o = baseline(); mut(hdr(o));
    return failing(o, id).map((f) => f.fingerprint.split("|")[1]);
  };
  it("X-Frame-Options ALLOW-FROM / invalid", () => {
    expect(titleFor((h) => (h["x-frame-options"] = "ALLOW-FROM https://a.com"))).toContain("xfo");
    expect(titleFor((h) => (h["x-frame-options"] = "DENY, SAMEORIGIN"))).toContain("xfo");
  });
  it("HSTS without max-age", () => {
    expect(titleFor((h) => (h["strict-transport-security"] = "includeSubDomains"))).toContain("hsts-no-maxage");
  });
  it("CSP with unquoted keywords", () => {
    expect(titleFor((h) => (h["content-security-policy"] = "default-src self; script-src none"))).toContain("csp-unquoted");
    expect(titleFor((h) => (h["content-security-policy"] = "default-src 'self'"))).toHaveLength(0);
  });
  it("Referrer-Policy / Permissions-Policy garbage", () => {
    expect(titleFor((h) => (h["referrer-policy"] = "banana"))).toContain("referrer");
    expect(titleFor((h) => (h["permissions-policy"] = "camera none"))).toContain("permissions");
    expect(titleFor((h) => (h["permissions-policy"] = "geolocation=(self), camera=()"))).toHaveLength(0);
  });
  it("meta CSP with ignored directives", () => {
    const o = baseline(); delete hdr(o)["content-security-policy"];
    setHtml(o, `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; frame-ancestors 'none'">`);
    expect(failing(o, id).map((f) => f.fingerprint.split("|")[1])).toContain("csp-meta-ignored");
  });
  it("deprecated X-XSS-Protection is informational", () => {
    const o = baseline(); hdr(o)["x-xss-protection"] = "1; mode=block";
    const f = run(o, id).find((x) => x.title.includes("X-XSS"))!;
    expect(f.status).toBe("info");
  });
  it("passes when everything is well-formed", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

// ---------------------------------------------------------------- browser
describe("browser.mixed-content", () => {
  const id = "browser.mixed-content";
  it("http script on https page → Medium (active)", () => {
    const o = baseline(); setHtml(o, `<script src="http://cdn.example.net/x.js"></script>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
    expect(failing(o, id)[0]!.fingerprint).toMatch(/\|active$/);
  });
  it("http image → Low (passive)", () => {
    const o = baseline(); setHtml(o, `<img src="http://example.com/a.png">`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("both kinds produce two findings; https refs pass; http pages skipped", () => {
    const o = baseline(); setHtml(o, `<iframe src="http://x.test/"></iframe><img src="http://x.test/a.png">`);
    expect(failing(o, id)).toHaveLength(2);
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const p = baseline(); p.pageIsHttps = false;
    expect(run(p, id)).toHaveLength(0);
  });
});

describe("browser.third-party-integrity", () => {
  const id = "browser.third-party-integrity";
  it("flags CDN scripts without SRI (Low, medium confidence)", () => {
    const o = baseline(); setHtml(o, `<script src="https://cdn.jsdelivr.net/npm/x@1/x.js"></script>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "medium" });
  });
  it("ignores SRI-protected and non-CDN third parties", () => {
    const o = baseline(); setHtml(o, `<script src="https://cdn.jsdelivr.net/npm/x@1/x.js" integrity="sha384-abc" crossorigin="anonymous"></script><script src="https://analytics.vendor.com/a.js"></script>`);
    expect(failing(o, id)).toHaveLength(0);
  });
});

describe("browser.cors", () => {
  const id = "browser.cors";
  const origin = "https://vibesec-cors-probe.invalid";
  it("reflected origin + credentials → High (medium confidence)", () => {
    const o = baseline(); o.cors = { testedOrigin: origin, status: 200, acao: origin, acac: "true", vary: null };
    expect(failing(o, id)[0]).toMatchObject({ severity: "high", confidence: "medium" });
  });
  it("reflected origin without credentials → Low", () => {
    const o = baseline(); o.cors = { testedOrigin: origin, status: 200, acao: origin, acac: null, vary: "Origin" };
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("null origin → Medium", () => {
    const o = baseline(); o.cors = { testedOrigin: origin, status: 200, acao: "null", acac: null, vary: null };
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
  });
  it("wildcard: Low (tin cậy thấp), Low (tin cậy cao) khi kèm credentials", () => {
    const o = baseline(); o.cors = { testedOrigin: origin, status: 200, acao: "*", acac: null, vary: null };
    expect(run(o, id)[0]).toMatchObject({ status: "fail", severity: "low", confidence: "low" });
    o.cors = { testedOrigin: origin, status: 200, acao: "*", acac: "true", vary: null };
    expect(failing(o, id)[0]).toMatchObject({ severity: "low" });
  });
  it("fixed allow-listed origin and no ACAO pass", () => {
    const o = baseline(); o.cors = { testedOrigin: origin, status: 200, acao: "https://app.example.com", acac: "true", vary: "Origin" };
    expect(run(o, id)[0]!.status).toBe("pass");
    expect(run(baseline(), id)[0]!.status).toBe("pass");
  });
});

// ---------------------------------------------------------------- cookies
describe("cookies.flags", () => {
  const id = "cookies.flags";
  const withCookie = (c: string | string[]) => {
    const o = baseline(); hdr(o)["set-cookie"] = c; o.https!.chain[0]!.headers = hdr(o);
    return o;
  };
  it("session cookie with no flags → Medium", () => {
    const f = failing(withCookie("session=abc123; Path=/"), id)[0]!;
    expect(f).toMatchObject({ severity: "medium", confidence: "high" });
    expect(f.summary).toContain("Secure");
    expect(f.summary).toContain("HttpOnly");
  });
  it("evidence never contains the cookie value", () => {
    const f = failing(withCookie("session=SUPERSECRETVALUE; Path=/"), id)[0]!;
    expect(JSON.stringify(f)).not.toContain("SUPERSECRETVALUE");
    expect(f.evidence[0]).toContain("session=<đã che>");
  });
  it("benign cookie missing only HttpOnly/SameSite is not a failure", () => {
    expect(failing(withCookie("theme=dark; Secure; Path=/"), id)).toHaveLength(0);
  });
  it("non-session cookie missing Secure on HTTPS → Low", () => {
    expect(failing(withCookie("theme=dark; Path=/; SameSite=Lax"), id)[0]).toMatchObject({ severity: "low" });
  });
  it("SameSite=None without Secure → Medium", () => {
    expect(failing(withCookie("pref=1; SameSite=None"), id)[0]).toMatchObject({ severity: "medium" });
  });
  it("__Host- prefix violations", () => {
    expect(failing(withCookie("__Host-sid=1; Secure; HttpOnly; SameSite=Lax; Path=/app"), id)[0]!.summary).toContain("__Host-");
  });
  it("well-configured cookie passes; no cookies passes", () => {
    expect(run(withCookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/"), id)[0]!.status).toBe("pass");
    expect(run(baseline(), id)[0]!.title).toContain("không đặt cookie");
  });
  it("one finding per cookie", () => {
    const f = failing(withCookie(["a_session=1; Path=/", "b_token=2; Path=/"]), id);
    expect(new Set(f.map((x) => x.fingerprint)).size).toBe(2);
  });
  it("parseSetCookie", () => {
    expect(parseSetCookie("a=b; Secure; HttpOnly; SameSite=Strict; Max-Age=86400; Path=/; Domain=x.com", "u")).toMatchObject({ name: "a", secure: true, httpOnly: true, sameSite: "strict", path: "/", domain: "x.com", maxAgeDays: 1 });
    expect(parseSetCookie("garbage", "u")).toBeNull();
  });
});

describe("cookies.cache-control-sensitive", () => {
  const id = "cookies.cache-control-sensitive";
  const loginPage = (cc?: string) => {
    const o = baseline();
    const { "cache-control": _drop, ...noCache } = GOOD_HEADERS; void _drop;
    const headers = { ...noCache, ...(cc ? { "cache-control": cc } : {}), "set-cookie": "sid=1; Secure; HttpOnly; SameSite=Lax" };
    o.sensitivePage = rec({ requestedUrl: "https://example.com/login", finalUrl: "https://example.com/login", headers, body: `<input type="password">` });
    return o;
  };
  it("login page with public caching and a session cookie → Medium", () => {
    expect(failing(loginPage("public, max-age=3600"), id)[0]).toMatchObject({ severity: "medium", confidence: "medium" });
  });
  it("login page with no Cache-Control → Low, low confidence", () => {
    expect(failing(loginPage(), id)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });
  it("no-store / private pass", () => {
    expect(run(loginPage("no-store"), id)[0]!.status).toBe("pass");
    expect(run(loginPage("private, no-cache"), id)[0]!.status).toBe("pass");
  });
  it("ordinary public pages are not flagged", () => {
    expect(run(baseline(), id)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------- exposure
describe("exposure.secrets", () => {
  const id = "exposure.secrets";
  const withScript = (code: string) => {
    const o = baseline();
    o.scripts = [{ url: "https://example.com/app.js", inline: false, sameOrigin: true, content: code }];
    return o;
  };
  it("Stripe live key → Critical, redacted", () => {
    const key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
    const f = failing(withScript(`const k="${key}"`), id)[0]!;
    expect(f).toMatchObject({ severity: "critical", confidence: "high" });
    expect(JSON.stringify(f)).not.toContain(key);
  });
  it("Supabase service_role JWT → Critical; anon → Info", () => {
    const jwt = (p: object) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify(p)).toString("base64url")}.abcdefghijklmnop`;
    expect(failing(withScript(`x="${jwt({ iss: "supabase", role: "service_role" })}"`), id)[0]).toMatchObject({ severity: "critical" });
    const anon = run(withScript(`x="${jwt({ iss: "supabase", ref: "abc", role: "anon" })}"`), id)[0]!;
    expect(anon).toMatchObject({ status: "info", severity: "info" });
  });
  it("private key and DB URL with password", () => {
    expect(failing(withScript("-----BEGIN RSA PRIVATE KEY-----\nMIIE"), id)[0]!.severity).toBe("critical");
    expect(failing(withScript('const u="postgres://app:hunter22secret@db.internal.net:5432/prod"'), id)[0]!.severity).toBe("critical");
  });
  it("secrets in the page HTML are detected too", () => {
    const o = baseline(); o.https!.body = `<script>var t="ghp_${"a".repeat(36)}"</script>`;
    expect(failing(o, id)[0]!.severity).toBe("critical");
  });
  it("false-positive guards: placeholders, localhost DB, test-ish words, short tokens", () => {
    const code = `
      const aws="AKIAIOSFODNN7EXAMPLE";
      const db="postgres://user:password@localhost:5432/dev";
      const db2="postgres://user:<password>@host/db";
      const s="sk_live_xxxx";
      const slack="xoxb-your-token-here";
      const rand="eyJhbGciOiJIUzI1NiJ9.e30.aaaaaaaaaaaa";
      const pk="pk_live_51Habcdefghijklmnopqrstuvwx";`;
    expect(failing(withScript(code), id)).toHaveLength(0);
  });
  it("Google API key is informational (public by design)", () => {
    const f = run(withScript(`k="AIza${"A".repeat(35)}"`), id)[0]!;
    expect(f).toMatchObject({ status: "info", severity: "info" });
  });
  it("passes on clean content", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

describe("exposure.public-config", () => {
  const id = "exposure.public-config";
  it("lists NEXT_PUBLIC values as info and flags secret-sounding names Medium", () => {
    const o = baseline();
    o.scripts = [{ url: "https://example.com/app.js", inline: false, sameOrigin: true, content: `{"NEXT_PUBLIC_API_URL":"https://api.example.com","NEXT_PUBLIC_STRIPE_SECRET_KEY":"abcdefghij1234"}` }];
    const all = run(o, id);
    expect(all.find((f) => f.status === "fail")).toMatchObject({ severity: "medium", confidence: "medium" });
    expect(all.find((f) => f.status === "info")!.evidence.join()).toContain("NEXT_PUBLIC_API_URL");
    expect(JSON.stringify(all)).not.toContain("abcdefghij1234");
  });
  it("silent when nothing present", () => expect(run(baseline(), id)).toHaveLength(0));
});

describe("exposure.source-maps", () => {
  const id = "exposure.source-maps";
  it("exposed map → Medium", () => {
    const o = baseline(); o.sourceMaps = [{ scriptUrl: "https://example.com/app.js", mapUrl: "https://example.com/app.js.map", exposed: true, status: 200 }];
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });
  it("Next.js hint only when Next.js detected", () => {
    const o = baseline(); o.sourceMaps = [{ scriptUrl: "u", mapUrl: "https://example.com/a.map", exposed: true, status: 200 }];
    expect(failing(o, id)[0]!.remediation!.snippets).toHaveLength(0);
    o.platforms = ["nextjs"];
    expect(failing(o, id)[0]!.remediation!.snippets[0]!.code).toContain("productionBrowserSourceMaps");
  });
  it("referenced but 404 passes; none referenced is silent", () => {
    const o = baseline(); o.sourceMaps = [{ scriptUrl: "u", mapUrl: "https://example.com/a.map", exposed: false, status: 404 }];
    expect(run(o, id)[0]!.status).toBe("pass");
    expect(run(baseline(), id)).toHaveLength(0);
  });
});

describe("exposure files", () => {
  it("robots.txt: missing → info; sensitive Disallow → info (low confidence); fine → pass", () => {
    const o = baseline(); o.files.robots = { url: "u", present: false, status: 404, contentType: "", body: "" };
    expect(run(o, "exposure.robots-txt")[0]).toMatchObject({ status: "info" });
    o.files.robots = { url: "u", present: true, status: 200, contentType: "text/plain", body: "User-agent: *\nDisallow: /admin-backup/\nDisallow: /cart" };
    expect(run(o, "exposure.robots-txt")[0]).toMatchObject({ status: "info", confidence: "low" });
    expect(run(baseline(), "exposure.robots-txt")[0]!.status).toBe("pass");
  });
  it("sitemap.xml: missing → info; present → pass", () => {
    const o = baseline(); o.files.sitemap = { url: "u", present: false, status: 404, contentType: "", body: "" };
    expect(run(o, "exposure.sitemap-xml")[0]).toMatchObject({ status: "info" });
    expect(run(baseline(), "exposure.sitemap-xml")[0]!.status).toBe("pass");
  });
  it("security.txt: missing → Low with a template; expired/contactless → Low; valid → pass", () => {
    const o = baseline(); o.files.securityTxt = { url: "u", present: false, status: 404, contentType: "", body: "" };
    const miss = run(o, "exposure.security-txt")[0]!;
    expect(miss).toMatchObject({ status: "fail", severity: "low", confidence: "medium" });
    expect(miss.remediation!.snippets[0]!.code).toContain("Contact:");
    o.files.securityTxt = { url: "u", present: true, status: 200, contentType: "text/plain", body: "Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z" };
    expect(failing(o, "exposure.security-txt")[0]!.summary).toContain("hết hạn");
    o.files.securityTxt = { url: "u", present: true, status: 200, contentType: "text/plain", body: "Expires: 2099-01-01T00:00:00Z" };
    expect(failing(o, "exposure.security-txt")[0]!.summary).toContain("thiếu trường Contact");
    expect(run(baseline(), "exposure.security-txt")[0]!.status).toBe("pass");
  });
});

// ---------------------------------------------------------------- configuration
describe("config.server-disclosure", () => {
  const id = "config.server-disclosure";
  it("versioned Server / X-Powered-By → Low", () => {
    const o = baseline(); hdr(o).server = "nginx/1.18.0"; hdr(o)["x-powered-by"] = "PHP/7.4.3";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "high" });
  });
  it("name only → info; none → pass", () => {
    const o = baseline(); hdr(o).server = "nginx";
    expect(run(o, id)[0]).toMatchObject({ status: "info" });
    expect(run(baseline(), id)[0]!.status).toBe("pass");
  });
  it("Next.js poweredByHeader fix only when detected", () => {
    const o = baseline(); hdr(o)["x-powered-by"] = "Next.js 14.2.1"; o.platforms = ["nextjs"];
    expect(failing(o, id)[0]!.remediation!.snippets[0]!.code).toContain("poweredByHeader: false");
  });
});

describe("config.suspicious-redirects", () => {
  const id = "config.suspicious-redirects";
  it("https → http downgrade → Medium", () => {
    const o = baseline();
    o.https!.chain = [{ url: HOME, status: 302, headers: { location: "http://example.com/" } }, { url: "http://example.com/", status: 200, headers: {} }];
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });
  it("long chains and raw-IP redirects → Low", () => {
    const o = baseline();
    o.http!.chain = Array.from({ length: 6 }, (_, i) => ({ url: `https://example.com/${i}`, status: 301, headers: {} }));
    expect(failing(o, id).map((f) => f.fingerprint.split("|")[1])).toContain("long:http");
    const p = baseline();
    p.http!.chain = [{ url: "http://example.com/", status: 302, headers: {} }, { url: "http://93.184.216.34/", status: 200, headers: {} }];
    expect(failing(p, id).map((f) => f.fingerprint.split("|")[1])).toContain("ip:http");
  });
  it("cross-domain redirect is informational; meta refresh cross-domain → Low", () => {
    const o = baseline();
    o.https!.chain = [{ url: "https://old-brand.com/", status: 301, headers: {} }, { url: HOME, status: 200, headers: {} }];
    expect(run(o, id)[0]).toMatchObject({ status: "info" });
    const p = baseline(); setHtml(p, `<meta http-equiv="refresh" content="0;url=https://evil.org/">`);
    expect(failing(p, id)[0]).toMatchObject({ severity: "low" });
  });
  it("refused redirect to a private address is reported as info", () => {
    const o = baseline();
    o.https!.error = { code: "non_public_ip", message: "blocked", blocked: true };
    expect(run(o, id).some((f) => f.status === "info" && f.fingerprint.endsWith("|blocked:https"))).toBe(true);
  });
  it("passes when clean", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

describe("config.dns-email-security", () => {
  const id = "config.dns-email-security";
  it("missing DMARC/SPF → Low with LOW confidence (domain may not send mail)", () => {
    const o = baseline(); o.dns = { domain: "example.com", caa: [], spf: null, dmarc: null };
    const f = failing(o, id);
    expect(f.map((x) => x.severity)).toEqual(["low", "low", "low"]); // DMARC, SPF, CAA
    expect(f.every((x) => x.confidence === "low")).toBe(true);
    expect(f.some((x) => x.fingerprint.endsWith("|caa"))).toBe(true);
  });
  it("lookup failures (undefined) produce nothing", () => {
    const o = baseline(); o.dns = { domain: "example.com", caa: null, spf: undefined, dmarc: undefined };
    expect(run(o, id)).toHaveLength(0);
  });
  it("silent for IP hosts", () => {
    const o = baseline(); o.dns = { domain: null, caa: null, spf: null, dmarc: null };
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("config.technology & config.auth-surface", () => {
  it("lists detected technologies (info, medium confidence)", () => {
    const o = baseline(); o.technologies = ["React", "Next.js"];
    expect(run(o, "config.technology")[0]).toMatchObject({ status: "info", confidence: "medium" });
    o.technologies = [];
    expect(run(o, "config.technology")).toHaveLength(0);
  });
  it("auth-surface notes login forms and auth providers (never a failure)", () => {
    const o = baseline(); o.technologies = ["Supabase"]; setHtml(o, `<form method="post"><input type="password"></form>`);
    const f = run(o, "config.auth-surface")[0]!;
    expect(f.status).toBe("info");
    expect(f.evidence.join()).toContain("Row Level Security");
  });
});

// ---------------------------------------------------------------- privacy
describe("privacy rules", () => {
  it("referrer-policy: missing → Low; unsafe-url → Low; meta fallback; good → pass", () => {
    const o = baseline(); delete hdr(o)["referrer-policy"];
    expect(failing(o, "privacy.referrer-policy")[0]).toMatchObject({ severity: "low" });
    hdr(o)["referrer-policy"] = "unsafe-url";
    expect(failing(o, "privacy.referrer-policy")[0]!.title).toContain("lộ URL");
    delete hdr(o)["referrer-policy"];
    setHtml(o, `<meta name="referrer" content="same-origin">`);
    o.html!.metaReferrer = "same-origin";
    expect(run(o, "privacy.referrer-policy")[0]!.status).toBe("pass");
    expect(run(baseline(), "privacy.referrer-policy")[0]!.status).toBe("pass");
  });
  it("permissions-policy: missing is informational only", () => {
    const o = baseline(); delete hdr(o)["permissions-policy"];
    expect(run(o, "privacy.permissions-policy")[0]).toMatchObject({ status: "info", severity: "info" });
    expect(run(baseline(), "privacy.permissions-policy")[0]!.status).toBe("pass");
  });
  it("third-party-origins: lists external hosts; same-site subdomains don't count", () => {
    const o = baseline(); setHtml(o, `<script src="https://www.googletagmanager.com/gtm.js"></script><img src="https://static.example.com/a.png">`);
    const f = run(o, "privacy.third-party-origins")[0]!;
    expect(f.status).toBe("info");
    expect(f.evidence).toEqual(["www.googletagmanager.com"]);
    expect(run(baseline(), "privacy.third-party-origins")[0]!.status).toBe("pass");
  });
});
