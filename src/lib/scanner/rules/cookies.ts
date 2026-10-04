import { cookieFix } from "../remediation";
import type { Finding, Observations, Rule, Severity } from "../types";
import { header, isHtml, livePage, makeFinding, MDN, pass, setCookies } from "../util";

const CAT = "Cookies & Sessions" as const;
const SESSION_NAME = /(sess|sid\b|^sid|auth|token|jwt|login|remember|identity|connect\.sid|next-auth|__session|sb-.*-auth)/i;
const CSRF_NAME = /csrf|xsrf/i;

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "lax" | "strict" | "none" | null;
  path: string | null;
  domain: string | null;
  maxAgeDays: number | null;
  source: string;
}

export function parseSetCookie(raw: string, source: string): ParsedCookie | null {
  const parts = raw.split(";").map((p) => p.trim());
  const eq = parts[0]!.indexOf("=");
  if (eq <= 0) return null;
  const c: ParsedCookie = { name: parts[0]!.slice(0, eq), secure: false, httpOnly: false, sameSite: null, path: null, domain: null, maxAgeDays: null, source };
  for (const a of parts.slice(1)) {
    const [k, ...rest] = a.split("=");
    const key = k!.toLowerCase();
    const val = rest.join("=");
    if (key === "secure") c.secure = true;
    else if (key === "httponly") c.httpOnly = true;
    else if (key === "samesite") c.sameSite = (["lax", "strict", "none"].includes(val.toLowerCase()) ? val.toLowerCase() : null) as ParsedCookie["sameSite"];
    else if (key === "path") c.path = val;
    else if (key === "domain") c.domain = val;
    else if (key === "max-age" && /^\d+$/.test(val)) c.maxAgeDays = Number(val) / 86400;
  }
  return c;
}

function collectCookies(obs: Observations): ParsedCookie[] {
  const seen = new Map<string, ParsedCookie>();
  const records = [obs.https, obs.sensitivePage, obs.page].filter((r): r is NonNullable<typeof r> => !!r);
  for (const r of records) {
    for (const hop of r.chain) {
      for (const raw of setCookies(hop.headers)) {
        const c = parseSetCookie(raw, hop.url);
        if (c) seen.set(c.name, c);
      }
    }
  }
  return [...seen.values()];
}

/** Redacted evidence: attribute flags only, never the value. */
function cookieEvidence(c: ParsedCookie): string {
  return [`${c.name}=<redacted>`, c.secure ? "Secure" : "", c.httpOnly ? "HttpOnly" : "", c.sameSite ? `SameSite=${c.sameSite}` : "", c.path ? `Path=${c.path}` : "", c.domain ? `Domain=${c.domain}` : ""].filter(Boolean).join("; ");
}

const cookieFlags: Rule = {
  id: "cookies.flags",
  title: "Cookies use Secure, HttpOnly and SameSite",
  category: CAT,
  run(obs) {
    if (!obs.page) return [];
    const cookies = collectCookies(obs);
    const url = obs.page.finalUrl;
    const refs = [MDN("Web/HTTP/Guides/Cookies", "MDN: Using HTTP cookies"), MDN("Web/HTTP/Reference/Headers/Set-Cookie", "MDN: Set-Cookie")];
    if (cookies.length === 0) {
      return [pass({ ruleId: this.id, title: "No cookies were set on first visit", category: CAT, affectedUrl: url, summary: "The site didn't set any cookies on an anonymous request.", explanation: "Nothing to misconfigure — and no consent banner needed for first-load cookies.", evidence: [] })];
    }
    const out: Finding[] = [];
    const secureSite = obs.pageIsHttps;
    for (const c of cookies) {
      const session = SESSION_NAME.test(c.name) && !CSRF_NAME.test(c.name);
      const problems: string[] = [];
      let sev: Severity = "info";
      const bump = (s: Severity) => { const order: Severity[] = ["critical", "high", "medium", "low", "info"]; if (order.indexOf(s) < order.indexOf(sev)) sev = s; };
      if (secureSite && !c.secure) { problems.push("Secure"); bump(session ? "medium" : "low"); }
      if (!c.httpOnly && !CSRF_NAME.test(c.name)) { problems.push("HttpOnly"); bump(session ? "medium" : "info"); }
      if (!c.sameSite) { problems.push("SameSite"); bump(session ? "low" : "info"); }
      const extra: string[] = [];
      if (c.sameSite === "none" && !c.secure) { extra.push("SameSite=None requires Secure; browsers reject this cookie"); bump("medium"); }
      if (c.name.startsWith("__Host-") && (!c.secure || c.path !== "/" || c.domain)) { extra.push("__Host- prefix requires Secure, Path=/ and no Domain"); bump("low"); }
      if (c.name.startsWith("__Secure-") && !c.secure) { extra.push("__Secure- prefix requires Secure"); bump("low"); }
      if (problems.length === 0 && extra.length === 0) continue;
      // Non-session cookies missing only HttpOnly/SameSite are not worth a failing finding.
      if (sev === "info") continue;
      out.push(makeFinding({
        ruleId: this.id, key: c.name, title: `Cookie "${c.name}" is missing security flags`, category: CAT, severity: sev,
        confidence: session ? "high" : "medium", status: "fail", affectedUrl: url, references: refs,
        summary: `${session ? "This looks like a session/auth cookie. " : ""}${[problems.length ? `Missing: ${problems.join(", ")}.` : "", ...extra].filter(Boolean).join(" ")}`,
        explanation: "Without Secure the cookie can leak over plain HTTP; without HttpOnly any injected script can steal it; without SameSite other sites can trigger authenticated requests (CSRF).",
        technical: `Set-Cookie flags observed for ${c.name} (value redacted).`, evidence: [cookieEvidence(c)],
        remediation: cookieFix(obs.platforms, [...problems, ...(c.sameSite === "none" && !c.secure ? ["Secure"] : [])].filter((v, i, a) => a.indexOf(v) === i)),
      }));
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `${cookies.length} cookie(s) set with appropriate flags.`, explanation: "Cookies are protected from interception, script access and cross-site use.", evidence: cookies.slice(0, 6).map(cookieEvidence), references: refs })];
    }
    return out;
  },
};

const SENSITIVE_PATH = /(login|signin|sign-in|account|admin|dashboard|profile|checkout|settings|billing|wp-admin)/i;

const cacheControl: Rule = {
  id: "cookies.cache-control-sensitive",
  title: "Sensitive pages are not cached",
  category: CAT,
  run(obs) {
    const candidates = [livePage(obs), obs.sensitivePage].filter((r): r is NonNullable<typeof r> => !!r && !r.error && r.status === 200 && isHtml(r.contentType));
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const r of candidates) {
      if (seen.has(r.finalUrl)) continue;
      seen.add(r.finalUrl);
      const isHome = r === obs.page;
      const path = new URL(r.finalUrl).pathname;
      const hasCookies = setCookies(r.headers).length > 0;
      const hasLogin = isHome ? obs.html?.hasPasswordInput === true : /type=["']?password/i.test(r.body);
      const sensitive = SENSITIVE_PATH.test(path) || hasLogin || (hasCookies && setCookies(r.headers).some((c) => SESSION_NAME.test(c.split("=")[0]!)));
      if (!sensitive) continue;
      const cc = (header(r.headers, "cache-control") ?? "").toLowerCase();
      const protectedCache = /no-store|private/.test(cc);
      const evidence = [`Cache-Control: ${cc || "(not present)"}`, ...(header(r.headers, "pragma") ? [`Pragma: ${header(r.headers, "pragma")}`] : [])];
      if (protectedCache) {
        out.push(pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: r.finalUrl, summary: "This sensitive-looking page tells caches not to store it.", explanation: "Private pages won't be kept by shared proxies or shown via the back button.", evidence }));
        continue;
      }
      const explicitPublic = /\bpublic\b|s-maxage|max-age=(?!0\b)\d+/.test(cc);
      out.push(makeFinding({
        ruleId: this.id, title: "Sensitive-looking page may be cached", category: CAT, severity: explicitPublic && hasCookies ? "medium" : "low", confidence: explicitPublic ? "medium" : "low", status: "fail",
        affectedUrl: r.finalUrl, references: [MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching")],
        summary: `This page looks like a login/account page (${hasLogin ? "contains a password field" : "URL or cookies suggest it"}) but doesn't send Cache-Control: no-store.`,
        explanation: "Shared caches (CDNs, corporate proxies) or the browser's back button could keep personal or session-specific content and show it to the wrong person.",
        technical: "Heuristic: sensitivity is inferred from the URL path, password inputs and session-like cookies — verify it applies to your authenticated pages.", evidence,
        remediation: { summary: "Send Cache-Control: no-store (or private, no-cache) on authenticated and account pages.", snippets: [] },
      }));
    }
    return out;
  },
};

export const cookieRules: Rule[] = [cookieFlags, cacheControl];
