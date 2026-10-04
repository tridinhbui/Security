import { getDomain } from "tldts";
import type { Finding, Observations, Rule } from "../types";
import { header, headerEvidence, livePage, makeFinding, MDN, pass, truncate } from "../util";

const CAT = "Configuration" as const;

const serverDisclosure: Rule = {
  id: "config.server-disclosure",
  title: "Server and framework versions are not disclosed",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const names = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime"];
    const present = names.filter((n) => header(p.headers, n) !== undefined);
    const versioned = present.filter((n) => /\d+\.\d+/.test(header(p.headers, n)!));
    const refs = [{ title: "OWASP WSTG: Fingerprint Web Server", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server" }];
    if (versioned.length) {
      return [makeFinding({
        ruleId: this.id, title: "Software versions revealed in response headers", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Headers reveal exact versions: ${versioned.map((n) => `${n}: ${truncate(header(p.headers, n)!, 60)}`).join("; ")}.`,
        explanation: "Attackers use version numbers to look up known vulnerabilities for your exact software. Hiding them isn't a fix for unpatched software, but it removes a free hint.",
        technical: "Version strings in Server / X-Powered-By style headers.", evidence: present.map((n) => headerEvidence(p.headers, n)),
        remediation: {
          summary: "Remove version details (and X-Powered-By) from responses — and keep the software patched.",
          steps: ["Nginx: server_tokens off;", "Apache: ServerTokens Prod and ServerSignature Off", "Express: app.disable('x-powered-by') (or use helmet)", "Next.js: set poweredByHeader: false in next.config"],
          snippets: obs.platforms.includes("nextjs") ? [{ platform: "nextjs", label: "Next.js — next.config.ts", language: "ts", code: "const nextConfig = {\n  poweredByHeader: false,\n};\nexport default nextConfig;" }] : [],
        },
      })];
    }
    if (present.length) {
      return [makeFinding({ ruleId: this.id, title: "Technology names visible in response headers", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: p.finalUrl, references: refs,
        summary: `Headers name the stack (${present.join(", ")}) but no versions.`, explanation: "Low risk. Naming the technology is common and mostly harmless without a version.", evidence: present.map((n) => headerEvidence(p.headers, n)), remediation: null })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "No server or framework identification headers are exposed.", explanation: "Less information for attackers to work with.", evidence: [] })];
  },
};

const techFingerprint: Rule = {
  id: "config.technology",
  title: "Detected technologies",
  category: CAT,
  run(obs) {
    if (obs.technologies.length === 0 || !obs.page) return [];
    return [makeFinding({
      ruleId: this.id, title: "Frontend technology fingerprint", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `We detected: ${obs.technologies.join(", ")}.`, explanation: "Used to tailor fix instructions. Detection is based on public markers; it can be incomplete or wrong, and we only show framework-specific snippets when detection is reliable.",
      evidence: obs.technologies.map((t) => `• ${t}`), remediation: null,
    })];
  },
};

const REDIRECT_CHAIN_WARN = 4;

const redirects: Rule = {
  id: "config.suspicious-redirects",
  title: "Redirect behaviour",
  category: CAT,
  run(obs: Observations): Finding[] {
    const out: Finding[] = [];
    const records = [obs.https, obs.http].filter((r): r is NonNullable<typeof r> => !!r);
    for (const r of records) {
      const label = r === obs.https ? "https" : "http";
      const hops = r.chain;
      // Downgrade: an https URL redirecting to http.
      for (let i = 0; i < hops.length - 1; i++) {
        const cur = hops[i]!, next = hops[i + 1]!;
        if (cur.url.startsWith("https://") && next.url.startsWith("http://")) {
          out.push(makeFinding({ ruleId: this.id, key: `downgrade:${label}`, title: "Redirect downgrades from HTTPS to HTTP", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: cur.url,
            references: [MDN("Web/HTTP/Guides/Redirections", "MDN: Redirections")],
            summary: "A secure HTTPS URL redirects visitors to an unencrypted http:// URL.", explanation: "Visitors leave the encrypted connection mid-way, which defeats HTTPS entirely for those requests.",
            evidence: [`${cur.status} ${cur.url} → ${next.url}`], remediation: { summary: "Redirect to the https:// version of the URL (check your redirect rules, canonical-host settings and proxy headers like X-Forwarded-Proto).", snippets: [] } }));
          break;
        }
      }
      if (hops.length > REDIRECT_CHAIN_WARN) {
        out.push(makeFinding({ ruleId: this.id, key: `long:${label}`, title: "Long redirect chain", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: hops[0]?.url ?? null,
          summary: `Reaching the page takes ${hops.length} hops.`, explanation: "Long chains slow the site, and each extra hop is another place for downgrade or hijack mistakes.",
          evidence: hops.map((h) => `${h.status} ${truncate(h.url, 120)}`), remediation: { summary: "Redirect straight to the final canonical URL in a single step.", snippets: [] } }));
      }
      const ipHop = hops.slice(1).find((h) => /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:|\/|$)|^https?:\/\/\[/.test(h.url));
      if (ipHop) {
        out.push(makeFinding({ ruleId: this.id, key: `ip:${label}`, title: "Redirect to a raw IP address", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: hops[0]?.url ?? null,
          summary: "The site redirects visitors to an IP address instead of a domain name.", explanation: "IP-address URLs can't have a normal HTTPS certificate and are a pattern often seen in compromised or misconfigured sites.",
          evidence: [`→ ${truncate(ipHop.url, 160)}`], remediation: { summary: "Redirect to your domain name.", snippets: [] } }));
      }
      if (r.error?.blocked && hops.length > 0) {
        out.push(makeFinding({ ruleId: this.id, key: `blocked:${label}`, title: "Redirect to a non-public address was refused", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: hops[0]?.url ?? null,
          summary: "The site redirected to a destination VibeSec will not connect to (private, internal or non-standard).", explanation: "We only scan public websites on standard ports. If this redirect is unintended, check for misconfiguration or compromise.",
          evidence: [`${r.error.code}: ${r.error.message}`], remediation: null }));
      }
    }
    const main = obs.page;
    if (main && obs.html?.metaRefresh) {
      const m = /url\s*=\s*['"]?([^'";\s]+)/i.exec(obs.html.metaRefresh);
      if (m) {
        try {
          const target = new URL(m[1]!, main.finalUrl);
          const a = getDomain(target.hostname), b = getDomain(new URL(main.finalUrl).hostname);
          if (a && b && a !== b) out.push(makeFinding({ ruleId: this.id, key: "meta-refresh", title: "Page auto-redirects to another domain", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: main.finalUrl,
            summary: `A <meta refresh> sends visitors to ${target.hostname}.`, explanation: "Meta-refresh redirects to other sites are a common sign of hijacked pages or parked domains.", evidence: [`<meta http-equiv="refresh" content="${truncate(obs.html.metaRefresh, 120)}">`], remediation: { summary: "Confirm the redirect is intended; otherwise remove it and investigate.", snippets: [] } }));
        } catch { /* ignore invalid URLs */ }
      }
    }
    if (obs.https && obs.https.chain.length > 0) {
      const first = new URL(obs.https.chain[0]!.url).hostname;
      const last = new URL(obs.https.finalUrl).hostname;
      const a = getDomain(first), b = getDomain(last);
      if (a && b && a !== b && out.length === 0) {
        out.push(makeFinding({ ruleId: this.id, key: "cross-domain", title: "Site redirects to a different domain", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: obs.https.chain[0]!.url,
          summary: `${first} redirects to ${last}.`, explanation: "Common for rebrands and canonical domains. Worth a glance to confirm it is expected.", evidence: obs.https.chain.map((h) => `${h.status} ${truncate(h.url, 120)}`), remediation: null }));
      }
    }
    if (out.length === 0 && records.length) {
      return [pass({ ruleId: this.id, title: "No suspicious redirects", category: CAT, affectedUrl: obs.https?.requestedUrl ?? null, summary: "Redirects (if any) stay on the same site and never downgrade to HTTP.", explanation: "Visitors end up where they expect.", evidence: [] })];
    }
    return out;
  },
};

const dnsRule: Rule = {
  id: "config.dns-email-security",
  title: "DNS security metadata",
  category: CAT,
  run(obs) {
    const d = obs.dns;
    if (!d || !d.domain) return [];
    const out: Finding[] = [];
    const refs = [{ title: "dmarc.org overview", url: "https://dmarc.org/overview/" }];
    if (d.dmarc === null) {
      out.push(makeFinding({ ruleId: this.id, key: "dmarc", title: "No DMARC record", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null, references: refs,
        summary: `${d.domain} has no DMARC policy in DNS.`, explanation: "Without DMARC, attackers can send email that appears to come from your domain (phishing). This matters if your domain sends — or could be abused to fake — email.",
        technical: `No TXT record at _dmarc.${d.domain}. Confidence is low because we can't know whether this domain sends email.`, evidence: [`TXT _dmarc.${d.domain}: (none)`],
        remediation: { summary: "Publish a DMARC record, starting in monitoring mode.", snippets: [{ platform: "generic", label: `TXT _dmarc.${d.domain}`, language: "text", code: `v=DMARC1; p=none; rua=mailto:dmarc@${d.domain}` }] } }));
    } else if (typeof d.dmarc === "string") {
      out.push(pass({ ruleId: this.id, title: "DMARC policy published", category: CAT, summary: "A DMARC record exists.", explanation: "Receivers can reject spoofed email for your domain.", evidence: [truncate(d.dmarc, 200)] }));
    }
    if (d.spf === null) {
      out.push(makeFinding({ ruleId: this.id, key: "spf", title: "No SPF record", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null, references: refs,
        summary: `${d.domain} has no SPF record.`, explanation: "SPF lists which servers may send email for your domain; without it spoofed mail is easier to deliver.",
        technical: `No TXT record beginning v=spf1 at ${d.domain}.`, evidence: [`TXT ${d.domain}: no v=spf1`],
        remediation: { summary: "Publish an SPF record listing your mail providers (or v=spf1 -all if the domain sends no mail).", snippets: [{ platform: "generic", label: `TXT ${d.domain} (domain sends no email)`, language: "text", code: "v=spf1 -all" }] } }));
    } else if (typeof d.spf === "string") {
      out.push(pass({ ruleId: this.id, title: "SPF record published", category: CAT, summary: "An SPF record exists.", explanation: "Mail receivers can verify legitimate senders.", evidence: [truncate(d.spf, 200)] }));
    }
    if (d.caa !== null && d.caa.length === 0) {
      out.push(makeFinding({ ruleId: this.id, key: "caa", title: "No CAA record", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: null,
        summary: "No CAA record restricts which certificate authorities may issue certificates for this domain.", explanation: "CAA is an optional safeguard against mis-issued certificates.", evidence: [`CAA ${d.domain}: (none)`],
        remediation: { summary: "Optionally add a CAA record for the CA you use.", snippets: [{ platform: "generic", label: `CAA ${d.domain}`, language: "text", code: '0 issue "letsencrypt.org"' }] } }));
    }
    return out;
  },
};

const authSurface: Rule = {
  id: "config.auth-surface",
  title: "Publicly observable authentication setup",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const hints: string[] = [];
    const joined = obs.technologies.join(",");
    if (/Supabase/.test(joined)) hints.push("Supabase (check Row Level Security on every table)");
    if (/Firebase/.test(joined)) hints.push("Firebase (check Security Rules for Firestore/Storage/RTDB)");
    const cookieNames = [...(obs.https?.chain ?? []).flatMap((h) => (Array.isArray(h.headers["set-cookie"]) ? h.headers["set-cookie"] : h.headers["set-cookie"] ? [h.headers["set-cookie"] as string] : []))].map((c) => c.split("=")[0]!);
    if (cookieNames.some((n) => /next-auth|authjs/i.test(n))) hints.push("Auth.js / NextAuth session cookie");
    if (cookieNames.some((n) => /^sb-.*-auth-token/i.test(n))) hints.push("Supabase Auth session cookie");
    if (obs.html.hasPasswordInput) hints.push("A password login form is present on this page");
    if (hints.length === 0) return [];
    return [makeFinding({ ruleId: this.id, title: "Authentication stack visible from outside", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `Observed: ${hints.join("; ")}.`, explanation: "This is expected and not a vulnerability. It tells you where to double-check access controls, because attackers can see the same clues.",
      evidence: hints, remediation: null })];
  },
};

export const configRules: Rule[] = [serverDisclosure, techFingerprint, redirects, dnsRule, authSurface];
