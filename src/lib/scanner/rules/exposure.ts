import { detectPublicConfig, detectSecrets } from "../secrets";
import type { Finding, Observations, Rule, Severity } from "../types";
import { makeFinding, MDN, pass, pathOf, truncate } from "../util";

const CAT = "Exposure" as const;

/** Every publicly served text document we fetched: homepage HTML, inline scripts, same-origin JS. */
function publicDocuments(obs: Observations): { url: string; text: string }[] {
  const docs: { url: string; text: string }[] = [];
  if (obs.page?.body) docs.push({ url: obs.page.finalUrl, text: obs.page.body });
  for (const s of obs.scripts) {
    const text = s.content ?? s.fetched?.body;
    if (text) docs.push({ url: s.url ?? `${obs.page?.finalUrl ?? obs.target.url}#inline-script`, text });
  }
  return docs;
}

const secrets: Rule = {
  id: "exposure.secrets",
  title: "No obvious secrets in public HTML/JavaScript",
  category: CAT,
  run(obs) {
    const docs = publicDocuments(obs);
    if (docs.length === 0) return [];
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const d of docs) {
      for (const m of detectSecrets(d.text)) {
        const key = `${m.id}|${m.redacted}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const byDesign = m.publicByDesign === true;
        out.push(makeFinding({
          ruleId: this.id, key: `${m.id}:${pathOf(d.url)}:${m.redacted}`,
          title: byDesign ? `${m.label} found in public code (public by design)` : `${m.label} exposed in public code`,
          category: CAT, severity: m.severity, confidence: m.confidence, status: byDesign ? "info" : "fail", affectedUrl: d.url,
          references: [{ title: "OWASP: Secrets Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" }],
          summary: byDesign ? `${m.label} appears in a public file. ${m.note}` : `A ${m.label.toLowerCase()} is readable by anyone who views the page source or loads the JavaScript.`,
          explanation: byDesign ? "These identifiers are intended to ship to browsers. Make sure they are restricted (by referrer/domain, or by database policies)." : "Anything served to the browser is public. Attackers scan the web continuously for exposed keys and abuse them within minutes.",
          technical: `${m.note} Matched with a provider-specific pattern; the full value is not stored.`,
          evidence: [`${m.label}: ${m.redacted}`, `Found in: ${truncate(d.url, 200)}`],
          remediation: byDesign
            ? { summary: "Restrict the key and verify access controls.", steps: m.id === "supabase-anon-key" ? ["Enable Row Level Security on every table and write explicit policies.", "Never expose the service_role key to the browser."] : ["In the Google Cloud console, restrict the key by HTTP referrer and by the specific APIs it may call."], snippets: [] }
            : { summary: "Treat this credential as compromised: revoke it now, then issue a new one and keep it server-side.", steps: ["Revoke/rotate the credential in the provider's dashboard immediately — deleting it from the code is not enough.", "Move the value to a server-side environment variable and call the provider from an API route or server action.", "Check the provider's audit log for unfamiliar activity.", "Never prefix server secrets with NEXT_PUBLIC_, VITE_, REACT_APP_ or similar — those are bundled into public JS."], snippets: [] },
        }));
      }
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, summary: `No known credential formats found in ${docs.length} public document(s).`, explanation: "Conservative pattern matching found no API keys, private keys or connection strings. This check can't prove their absence.", evidence: [`${docs.length} document(s) scanned`], technical: "Provider-specific patterns only; generic 'looks like a password' heuristics are intentionally not used to avoid false positives.", affectedUrl: obs.page?.finalUrl ?? null })];
    }
    return out;
  },
};

const publicConfig: Rule = {
  id: "exposure.public-config",
  title: "Client-side environment values",
  category: CAT,
  run(obs) {
    const docs = publicDocuments(obs);
    const entries = new Map<string, { len: number; sensitive: boolean; url: string }>();
    for (const d of docs) for (const e of detectPublicConfig(d.text)) if (!entries.has(e.key)) entries.set(e.key, { len: e.valueLength, sensitive: e.sensitiveName, url: d.url });
    if (entries.size === 0) return [];
    const sensitive = [...entries.entries()].filter(([, v]) => v.sensitive);
    const out: Finding[] = [];
    if (sensitive.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "sensitive-names", title: "Public config contains secret-sounding variables", category: CAT, severity: "medium", confidence: "medium", status: "fail", affectedUrl: sensitive[0]![1].url,
        summary: `${sensitive.length} build-time variable(s) with names like SECRET/PRIVATE/PASSWORD are bundled into public JavaScript.`,
        explanation: "Variables with public prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_…) are copied into the browser bundle for everyone. A name that sounds secret suggests something private was exposed by mistake.",
        technical: "Heuristic on variable names; values are not inspected beyond length and are never stored.",
        evidence: sensitive.slice(0, 10).map(([k, v]) => `${k} = <redacted, ${v.len} chars>`),
        remediation: { summary: "Remove the public prefix, keep the value server-side, rotate it if it was real, and rebuild.", snippets: [] },
      }));
    }
    const rest = [...entries.keys()].filter((k) => !entries.get(k)!.sensitive);
    if (rest.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "list", title: "Environment values delivered to the browser", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: entries.get(rest[0]!)!.url,
        summary: `${rest.length} configuration value(s) are embedded in public JavaScript.`,
        explanation: "This is normal for public settings like API base URLs and publishable keys. Just make sure none of them is actually private.",
        evidence: rest.slice(0, 15).map((k) => `${k} = <redacted, ${entries.get(k)!.len} chars>`),
        remediation: { summary: "Review this list: anything that would hurt if a stranger saw it must move server-side.", snippets: [] },
      }));
    }
    return out;
  },
};

const sourceMaps: Rule = {
  id: "exposure.source-maps",
  title: "Source maps are not public",
  category: CAT,
  run(obs) {
    if (obs.sourceMaps.length === 0) return [];
    const exposed = obs.sourceMaps.filter((s) => s.exposed);
    const refs = [MDN("Tools/Debugger/How_to/Use_a_source_map", "MDN: Source maps")];
    if (exposed.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: obs.sourceMaps[0]!.scriptUrl, summary: "Scripts reference source maps, but they are not publicly downloadable.", explanation: "Your original source code isn't exposed.", evidence: obs.sourceMaps.slice(0, 5).map((s) => `${s.mapUrl} → ${s.status}`), references: refs })];
    return [makeFinding({
      ruleId: this.id, title: "JavaScript source maps are publicly downloadable", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: exposed[0]!.mapUrl, references: refs,
      summary: `${exposed.length} source map file(s) referenced by the app's scripts can be downloaded by anyone.`,
      explanation: "Source maps reveal your original, readable source code — comments, file structure, internal API routes — making it far easier to find weaknesses. They may also contain secrets that were hard-coded.",
      technical: "A //# sourceMappingURL reference resolved to a 200 response that looks like a source map (JSON with version/sources).",
      evidence: exposed.slice(0, 6).map((s) => `${truncate(s.mapUrl, 200)} → ${s.status}`),
      remediation: {
        summary: "Don't publish source maps in production, or upload them only to your error tracker.",
        steps: obs.platforms.includes("nextjs") ? ["Next.js: ensure productionBrowserSourceMaps is not enabled in next.config (it is false by default)."] : ["Disable source map output for production builds in your bundler, or block *.map at your web server/CDN."],
        snippets: obs.platforms.includes("nextjs") ? [{ platform: "nextjs", label: "Next.js — next.config.ts", language: "ts", code: "const nextConfig = {\n  productionBrowserSourceMaps: false,\n};\nexport default nextConfig;" }] : [],
      },
    })];
  },
};

function severityNone(): { severity: Severity } {
  return { severity: "info" };
}

const robots: Rule = {
  id: "exposure.robots-txt",
  title: "robots.txt",
  category: CAT,
  run(obs) {
    const f = obs.files.robots;
    if (!f) return [];
    if (!f.present) return [makeFinding({ ruleId: this.id, title: "No robots.txt found", category: CAT, ...severityNone(), confidence: "high", status: "info", affectedUrl: f.url, summary: "The site has no robots.txt.", explanation: "Not a security problem. A robots.txt only guides well-behaved crawlers (and must never be used to hide private pages).", evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`], remediation: null })];
    const interesting = f.body.split(/\r?\n/).map((l) => /^\s*disallow\s*:\s*(\S+)/i.exec(l)?.[1]).filter((p): p is string => !!p && /(admin|backup|private|secret|internal|staging|\.git|\.env|config|dump|database|db\b|phpmyadmin)/i.test(p));
    if (interesting.length) {
      return [makeFinding({ ruleId: this.id, title: "robots.txt lists sensitive-looking paths", category: CAT, severity: "info", confidence: "low", status: "info", affectedUrl: f.url, summary: `robots.txt names ${interesting.length} path(s) that look private.`, explanation: "robots.txt is public. Listing 'hidden' paths there advertises them to attackers — it doesn't protect them. Real protection is authentication.", evidence: interesting.slice(0, 8).map((p) => `Disallow: ${p}`), remediation: { summary: "Make sure these paths require authentication; remove them from robots.txt if their existence is sensitive.", snippets: [] }, references: [{ title: "OWASP WSTG: Review Webserver Metafiles", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage" }] })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "robots.txt is present and doesn't advertise sensitive paths.", explanation: "Crawlers get guidance without revealing anything private.", evidence: [`${f.body.split(/\r?\n/).length} line(s)`] })];
  },
};

const sitemap: Rule = {
  id: "exposure.sitemap-xml",
  title: "sitemap.xml",
  category: CAT,
  run(obs) {
    const f = obs.files.sitemap;
    if (!f) return [];
    if (!f.present) return [makeFinding({ ruleId: this.id, title: "No sitemap.xml found", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: f.url, summary: "No sitemap.xml at the default location.", explanation: "Not a security issue; sitemaps help search engines. (It may exist at another path listed in robots.txt.)", evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`], remediation: null })];
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "sitemap.xml is present.", explanation: "Make sure it lists only pages meant to be public.", evidence: [`${f.contentType || "unknown type"}, ${f.body.length} bytes sampled`] })];
  },
};

const securityTxt: Rule = {
  id: "exposure.security-txt",
  title: "security.txt (vulnerability disclosure contact)",
  category: CAT,
  run(obs) {
    const f = obs.files.securityTxt;
    if (!f) return [];
    const refs = [{ title: "RFC 9116: security.txt", url: "https://www.rfc-editor.org/rfc/rfc9116" }, { title: "securitytxt.org", url: "https://securitytxt.org/" }];
    if (!f.present) {
      return [makeFinding({ ruleId: this.id, title: "No security.txt published", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: f.url, references: refs,
        summary: "There is no /.well-known/security.txt telling researchers how to report a vulnerability.", explanation: "Without a contact, well-meaning researchers who find a problem may not be able to reach you.",
        evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`],
        remediation: { summary: "Publish /.well-known/security.txt with a Contact and Expires field.", snippets: [{ platform: "generic", label: "/.well-known/security.txt", language: "text", code: "Contact: mailto:security@yourdomain.com\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: en\nCanonical: https://yourdomain.com/.well-known/security.txt" }] } })];
    }
    const contact = /^\s*Contact\s*:\s*\S+/im.test(f.body);
    const exp = /^\s*Expires\s*:\s*(\S+)/im.exec(f.body)?.[1];
    const expired = exp ? Date.parse(exp) < Date.now() : false;
    const problems = [!contact ? "no Contact field" : "", !exp ? "no Expires field" : "", expired ? `expired on ${exp}` : ""].filter(Boolean);
    if (problems.length) {
      return [makeFinding({ ruleId: this.id, title: "security.txt is incomplete or expired", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: f.url, references: refs,
        summary: `security.txt has problems: ${problems.join(", ")}.`, explanation: "An expired or contact-less security.txt is ignored by tooling and researchers.", evidence: [truncate(f.body.split(/\r?\n/).slice(0, 6).join(" | "), 300)],
        remediation: { summary: "Add a Contact and a future Expires date (RFC 9116).", snippets: [] } })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "security.txt is published with a contact and a valid expiry.", explanation: "Researchers know where to report problems.", evidence: [`Expires: ${exp}`], references: refs })];
  },
};

export const exposureRules: Rule[] = [secrets, publicConfig, sourceMaps, robots, sitemap, securityTxt];
