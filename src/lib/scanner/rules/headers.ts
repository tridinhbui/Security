import { headerFix, RECOMMENDED } from "../remediation";
import type { Finding, Observations, Rule, Severity } from "../types";
import { header, headerEvidence, isHtml, livePage, makeFinding, MDN, OWASP, pass, truncate } from "../util";

const CAT = "Headers" as const;

export interface Csp {
  directives: Map<string, string[]>;
}

export function parseCsp(value: string): Csp {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1)); // first occurrence wins per spec
  }
  return { directives };
}

/** Effective source list for scripts: script-src, falling back to default-src. */
function scriptSources(csp: Csp): string[] | null {
  return csp.directives.get("script-src") ?? csp.directives.get("default-src") ?? null;
}

const csp: Rule = {
  id: "headers.csp",
  title: "Content-Security-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const url = p.finalUrl;
    const refs = [MDN("Web/HTTP/Guides/CSP", "MDN: Content Security Policy"), OWASP("Content_Security_Policy_Cheat_Sheet.html", "OWASP CSP Cheat Sheet")];
    const enforced = header(p.headers, "content-security-policy");
    const reportOnly = header(p.headers, "content-security-policy-report-only");
    const meta = obs.html?.metaCsp ?? null;
    const policyText = enforced ?? meta;

    if (!policyText) {
      return [makeFinding({
        ruleId: this.id, title: reportOnly ? "CSP is report-only (not enforced)" : "Content-Security-Policy is missing", category: CAT,
        severity: reportOnly ? "low" : "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: reportOnly ? "A Content-Security-Policy is defined in report-only mode, so browsers log violations but don't block anything." : "The site doesn't restrict which scripts and resources the browser may load.",
        explanation: "A CSP is your best second line of defence against cross-site scripting (XSS): if an attacker manages to inject a script, the browser refuses to run it.",
        technical: reportOnly ? "Only Content-Security-Policy-Report-Only is present." : "No Content-Security-Policy header or meta tag.",
        evidence: [headerEvidence(p.headers, "content-security-policy"), ...(reportOnly ? [`Content-Security-Policy-Report-Only: ${truncate(reportOnly, 200)}`] : [])],
        remediation: headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Start with a strict policy, test it, and loosen only what your site genuinely needs. Roll out with Report-Only first if unsure."),
      })];
    }

    const parsed = parseCsp(policyText);
    const issues: { sev: Severity; text: string }[] = [];
    const scripts = scriptSources(parsed);
    if (scripts === null) {
      issues.push({ sev: "medium", text: "No script-src or default-src: scripts are unrestricted." });
    } else {
      const hasNonceOrHash = scripts.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
      const strictDynamic = scripts.includes("'strict-dynamic'");
      if (scripts.includes("'unsafe-inline'") && !hasNonceOrHash && !strictDynamic) issues.push({ sev: "medium", text: "script-src allows 'unsafe-inline', which defeats most XSS protection." });
      if (scripts.includes("'unsafe-eval'")) issues.push({ sev: "low", text: "script-src allows 'unsafe-eval'." });
      if (scripts.some((s) => s === "*" || s === "https:" || s === "http:" || s === "data:") && !strictDynamic) issues.push({ sev: "medium", text: "script-src allows scripts from any host (wildcard / scheme-only source)." });
    }
    const hasDefaultNone = parsed.directives.get("default-src")?.includes("'none'");
    if (!parsed.directives.has("object-src") && !hasDefaultNone && !(parsed.directives.get("default-src")?.includes("'self'"))) issues.push({ sev: "info", text: "object-src is not restricted (set object-src 'none')." });
    if (!parsed.directives.has("base-uri")) issues.push({ sev: "info", text: "base-uri is not set." });
    if (!enforced && meta) issues.push({ sev: "info", text: "Policy is delivered via <meta>, which cannot use frame-ancestors/report-uri; prefer an HTTP header." });

    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    const worst = issues.reduce<Severity | null>((w, i) => (w === null || order.indexOf(i.sev) < order.indexOf(w) ? i.sev : w), null);
    const evidence = [`Content-Security-Policy: ${truncate(policyText, 400)}`];
    if (!worst || worst === "info") {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "A Content-Security-Policy is enforced without obviously unsafe sources.", explanation: "Injected scripts are much less likely to run.", evidence: [...evidence, ...issues.map((i) => i.text)], references: refs })];
    }
    return [makeFinding({
      ruleId: this.id, title: "Content-Security-Policy is weak", category: CAT, severity: worst, confidence: "high", status: "fail", affectedUrl: url, references: refs,
      summary: issues.filter((i) => i.sev !== "info").map((i) => i.text).join(" "),
      explanation: "A CSP that allows inline scripts or any host gives much less protection against XSS than it appears to.",
      technical: issues.map((i) => `[${i.sev}] ${i.text}`).join("\n"), evidence,
      remediation: { ...headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes for inline scripts."), },
    })];
  },
};

const frameProtection: Rule = {
  id: "headers.frame-protection",
  title: "Clickjacking protection (X-Frame-Options / frame-ancestors)",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const xfo = header(p.headers, "x-frame-options")?.trim().toUpperCase();
    const fa = parseCsp(header(p.headers, "content-security-policy") ?? "").directives.get("frame-ancestors");
    const refs = [MDN("Web/HTTP/Reference/Headers/X-Frame-Options", "MDN: X-Frame-Options"), OWASP("Clickjacking_Defense_Cheat_Sheet.html", "OWASP Clickjacking Defense")];
    if (fa || xfo === "DENY" || xfo === "SAMEORIGIN") {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Other sites are prevented from embedding this page in a frame.", explanation: "Clickjacking attacks (invisible frames tricking users into clicking) are blocked.", evidence: [headerEvidence(p.headers, "x-frame-options"), `frame-ancestors: ${fa?.join(" ") ?? "(not set)"}`], references: refs })];
    }
    if (xfo) return []; // invalid value → headers.broken
    const sensitive = obs.html?.hasPasswordInput === true;
    return [makeFinding({
      ruleId: this.id, title: "Page can be embedded in other sites (clickjacking)", category: CAT, severity: sensitive ? "medium" : "low", confidence: sensitive ? "medium" : "high", status: "fail",
      affectedUrl: p.finalUrl, references: refs,
      summary: "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
      explanation: "A malicious site could load yours in an invisible frame and trick visitors into clicking buttons on it (e.g. 'Delete account').",
      technical: "No X-Frame-Options header and no frame-ancestors in the Content-Security-Policy.",
      evidence: [headerEvidence(p.headers, "x-frame-options"), headerEvidence(p.headers, "content-security-policy")],
      remediation: headerFix("X-Frame-Options", RECOMMENDED.xfo, obs.platforms, "Send X-Frame-Options: DENY (or SAMEORIGIN), or the modern equivalent CSP: frame-ancestors 'none'."),
    })];
  },
};

const xcto: Rule = {
  id: "headers.x-content-type-options",
  title: "X-Content-Type-Options",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const v = header(p.headers, "x-content-type-options")?.trim().toLowerCase();
    const refs = [MDN("Web/HTTP/Reference/Headers/X-Content-Type-Options", "MDN: X-Content-Type-Options")];
    if (v === "nosniff") return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Browsers are told not to guess content types.", explanation: "Prevents uploaded files being reinterpreted as scripts.", evidence: [headerEvidence(p.headers, "x-content-type-options")], references: refs })];
    if (v) return []; // wrong value → headers.broken
    return [makeFinding({
      ruleId: this.id, title: "X-Content-Type-Options is missing", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: "The nosniff header is not set.", explanation: "Without it, browsers may guess a file's type and sometimes run user-uploaded content as a script.",
      evidence: [headerEvidence(p.headers, "x-content-type-options")], remediation: headerFix("X-Content-Type-Options", RECOMMENDED.xcto, obs.platforms),
    })];
  },
};

const REFERRER_TOKENS = new Set(["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]);
const PERMISSION_DIRECTIVE = /^[a-z-]+=(\(.*\)|\*|self)$/i;

/** Detects syntactically wrong or obsolete security headers: present but not doing what the author intended. */
const brokenHeaders: Rule = {
  id: "headers.broken",
  title: "Security headers are well-formed",
  category: CAT,
  run(obs: Observations): Finding[] {
    const p = livePage(obs);
    if (!p) return [];
    const url = p.finalUrl;
    const out: Finding[] = [];
    const add = (key: string, title: string, severity: Severity, summary: string, evidence: string[], fix?: ReturnType<typeof headerFix>) =>
      out.push(makeFinding({ ruleId: this.id, key, title, category: CAT, severity, confidence: "high", status: "fail", affectedUrl: url, summary, explanation: "A header with an invalid value is usually ignored by browsers, so the protection you think you have isn't active.", evidence, remediation: fix ?? null, references: [MDN("Web/HTTP/Reference/Headers", "MDN: HTTP headers")] }));

    const xfo = header(p.headers, "x-frame-options");
    if (xfo && !["DENY", "SAMEORIGIN"].includes(xfo.trim().toUpperCase())) {
      add("xfo", "X-Frame-Options has an invalid value", "low", /allow-from/i.test(xfo) ? "ALLOW-FROM is obsolete and ignored by modern browsers." : `"${truncate(xfo, 60)}" is not a valid X-Frame-Options value (use DENY or SAMEORIGIN).`, [headerEvidence(p.headers, "x-frame-options")], headerFix("X-Frame-Options", RECOMMENDED.xfo, obs.platforms, "Use DENY or SAMEORIGIN, or CSP frame-ancestors."));
    }
    const x = header(p.headers, "x-content-type-options");
    if (x && x.trim().toLowerCase() !== "nosniff") add("xcto", "X-Content-Type-Options has an invalid value", "low", `"${truncate(x, 60)}" is not valid; the only accepted value is nosniff.`, [headerEvidence(p.headers, "x-content-type-options")], headerFix("X-Content-Type-Options", RECOMMENDED.xcto, obs.platforms));

    const hsts = header(obs.https && !obs.https.error ? obs.https.headers : undefined, "strict-transport-security");
    if (hsts) {
      const m = /max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
      if (!m) add("hsts-no-maxage", "HSTS header has no max-age", "medium", "Strict-Transport-Security without max-age is ignored by browsers.", [`Strict-Transport-Security: ${truncate(hsts, 200)}`], headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms));
      else if (Number(m[1]) === 0) add("hsts-zero", "HSTS is explicitly disabled (max-age=0)", "medium", "max-age=0 tells browsers to forget the HTTPS-only rule.", [`Strict-Transport-Security: ${truncate(hsts, 200)}`], headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms));
    }

    const cspH = header(p.headers, "content-security-policy");
    if (cspH) {
      const bareKeywords = /(?:^|[\s;])(self|none|unsafe-inline|unsafe-eval|strict-dynamic)(?=[\s;]|$)/i.exec(cspH.replace(/'[^']*'/g, ""));
      if (bareKeywords) add("csp-unquoted", "CSP uses an unquoted keyword", "medium", `"${bareKeywords[1]}" must be written with single quotes ('${bareKeywords[1]}'); unquoted it is treated as a hostname.`, [`Content-Security-Policy: ${truncate(cspH, 300)}`], headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms));
    }
    const meta = obs.html?.metaCsp;
    if (meta && !cspH && /frame-ancestors|report-uri|sandbox/i.test(meta)) add("csp-meta-ignored", "CSP <meta> contains directives browsers ignore", "low", "frame-ancestors, report-uri and sandbox have no effect when a CSP is delivered via <meta>.", [`<meta CSP>: ${truncate(meta, 300)}`], headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Send the policy as an HTTP header instead."));

    const rp = header(p.headers, "referrer-policy");
    if (rp) {
      const tokens = rp.split(",").map((t) => t.trim().toLowerCase());
      if (!tokens.some((t) => REFERRER_TOKENS.has(t))) add("referrer", "Referrer-Policy has an invalid value", "low", `"${truncate(rp, 60)}" is not a recognised policy.`, [headerEvidence(p.headers, "referrer-policy")], headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms));
    }
    const pp = header(p.headers, "permissions-policy");
    if (pp) {
      const bad = pp.split(/,(?![^()]*\))/).map((s) => s.trim()).filter(Boolean).find((d) => !PERMISSION_DIRECTIVE.test(d));
      if (bad) add("permissions", "Permissions-Policy is malformed", "low", `"${truncate(bad, 60)}" is not valid Permissions-Policy syntax (e.g. camera=(), geolocation=(self)).`, [headerEvidence(p.headers, "permissions-policy")], headerFix("Permissions-Policy", RECOMMENDED.permissions, obs.platforms));
    }
    const xss = header(p.headers, "x-xss-protection");
    if (xss && /^1/.test(xss.trim())) out.push(makeFinding({ ruleId: this.id, key: "xss-protection", title: "Deprecated X-XSS-Protection is enabled", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url, summary: "X-XSS-Protection: 1 relies on a removed browser filter and can introduce vulnerabilities in old browsers.", explanation: "Modern browsers ignore it. OWASP recommends setting it to 0 and relying on CSP instead.", evidence: [headerEvidence(p.headers, "x-xss-protection")], remediation: headerFix("X-XSS-Protection", "0", obs.platforms, "Set X-XSS-Protection: 0 (or remove it) and use a Content-Security-Policy."), references: [OWASP("HTTP_Headers_Cheat_Sheet.html", "OWASP HTTP Headers")] }));

    if (out.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "No malformed or contradictory security headers found.", explanation: "Headers that are present have valid values.", evidence: [] })];
    return out;
  },
};

export const headerRules: Rule[] = [csp, frameProtection, xcto, brokenHeaders];
