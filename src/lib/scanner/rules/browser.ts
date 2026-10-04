import type { Finding, Rule } from "../types";
import { makeFinding, MDN, pass, truncate } from "../util";

const CAT = "Browser Security" as const;
const ACTIVE_TAGS = new Set(["script", "link", "iframe", "object", "embed"]);
const SRI_CDN_HOSTS = /(^|\.)(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|cdn\.bootcss\.com)$/;

const mixedContent: Rule = {
  id: "browser.mixed-content",
  title: "No mixed content",
  category: CAT,
  run(obs) {
    if (!obs.pageIsHttps || !obs.html || !obs.page) return [];
    const insecure = obs.html.resources.filter((r) => r.url.startsWith("http://"));
    const url = obs.page.finalUrl;
    const refs = [MDN("Web/Security/Mixed_content", "MDN: Mixed content")];
    if (insecure.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "The page loads all its resources over HTTPS.", explanation: "Nothing on the page can be tampered with in transit.", evidence: [`${obs.html.resources.length} resource reference(s) checked`], references: refs })];
    }
    const active = insecure.filter((r) => ACTIVE_TAGS.has(r.tag));
    const out: Finding[] = [];
    if (active.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "active", title: "Page loads scripts or styles over HTTP", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `${active.length} script/style/frame resource(s) are referenced with http:// on an HTTPS page.`,
        explanation: "Browsers block these, so parts of your site likely break — and any that slip through can be replaced by an attacker to run code on your page.",
        technical: "Active mixed content (script/stylesheet/iframe/object/embed over http://).",
        evidence: active.slice(0, 8).map((r) => `<${r.tag} ${r.attr}="${truncate(r.url, 160)}">`),
        remediation: { summary: "Change every http:// reference to https:// (or a protocol-relative/relative URL). If the host has no HTTPS, host the file yourself or drop it.", steps: ["Add this to your CSP to upgrade stray requests automatically: upgrade-insecure-requests"], snippets: [] },
      }));
    }
    const passive = insecure.filter((r) => !ACTIVE_TAGS.has(r.tag));
    if (passive.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "passive", title: "Page loads images or media over HTTP", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `${passive.length} image/media resource(s) are referenced with http:// on an HTTPS page.`,
        explanation: "Browsers show a 'not fully secure' warning or upgrade them, and the content can be swapped by someone on the network.",
        technical: "Passive mixed content.", evidence: passive.slice(0, 8).map((r) => `<${r.tag} ${r.attr}="${truncate(r.url, 160)}">`),
        remediation: { summary: "Use https:// URLs for all images and media.", snippets: [] },
      }));
    }
    return out;
  },
};

const externalResources: Rule = {
  id: "browser.third-party-integrity",
  title: "Third-party CDN scripts use Subresource Integrity",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const url = obs.page.finalUrl;
    const missing: string[] = [];
    for (const s of obs.html.scripts) {
      if (!s.url || s.sameOrigin || s.integrity) continue;
      const host = new URL(s.url).hostname;
      if (SRI_CDN_HOSTS.test(host)) missing.push(s.url);
    }
    for (const c of obs.html.stylesheets) {
      if (c.sameOrigin || c.integrity) continue;
      if (SRI_CDN_HOSTS.test(new URL(c.href).hostname)) missing.push(c.href);
    }
    if (missing.length === 0) return [];
    return [makeFinding({
      ruleId: this.id, title: "CDN scripts/styles loaded without integrity checks", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: url,
      references: [MDN("Web/Security/Subresource_Integrity", "MDN: Subresource Integrity")],
      summary: `${missing.length} file(s) from a public CDN are loaded without an integrity attribute.`,
      explanation: "If the CDN (or the package on it) is compromised, attackers could change the file and run code on your site. An integrity hash makes the browser reject modified files.",
      technical: "Cross-origin <script>/<link rel=stylesheet> from a static CDN without integrity=\"sha384-…\".",
      evidence: missing.slice(0, 8).map((m) => truncate(m, 200)),
      remediation: { summary: 'Add integrity="sha384-…" and crossorigin="anonymous" to each tag, or self-host the file.', steps: ["Generate hashes with: openssl dgst -sha384 -binary file.js | openssl base64 -A  (or use srihash.org)", "Pin an exact version in the URL so the hash stays valid."], snippets: [] },
    })];
  },
};

const cors: Rule = {
  id: "browser.cors",
  title: "CORS configuration",
  category: CAT,
  run(obs) {
    const c = obs.cors;
    if (!c || c.status === null) return [];
    const url = obs.page?.finalUrl ?? obs.target.url;
    const refs = [MDN("Web/HTTP/Guides/CORS", "MDN: CORS"), { title: "PortSwigger: CORS", url: "https://portswigger.net/web-security/cors" }];
    const ev = [`Request Origin: ${c.testedOrigin}`, `Access-Control-Allow-Origin: ${c.acao ?? "(not present)"}`, `Access-Control-Allow-Credentials: ${c.acac ?? "(not present)"}`];
    const creds = c.acac?.toLowerCase() === "true";
    if (!c.acao) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "No cross-origin access is granted to unknown origins.", explanation: "Other websites can't read this site's responses from a visitor's browser.", evidence: ev, references: refs })];
    if (c.acao === c.testedOrigin) {
      return [makeFinding({
        ruleId: this.id, title: creds ? "CORS reflects any origin and allows credentials" : "CORS reflects any origin", category: CAT,
        severity: creds ? "high" : "low", confidence: creds ? "medium" : "medium", status: "fail", affectedUrl: url, references: refs,
        summary: creds ? "The server echoes back whatever Origin we sent and also allows cookies to be included." : "The server echoes back whatever Origin we sent.",
        explanation: creds ? "Any website a logged-in visitor opens could read this site's responses on their behalf — including private account data — if this applies to authenticated endpoints." : "Any website can read this response in a browser. That's fine for public content but dangerous if the same rule applies to private APIs.",
        technical: "Origin reflection (a random, unregistered origin was accepted).", evidence: ev,
        remediation: { summary: "Compare the Origin header to an explicit allow-list of trusted origins and only echo it on a match. Never combine credentialed CORS with a reflected or wildcard origin.", steps: ["Add Vary: Origin whenever the allowed origin depends on the request.", "Re-test your API endpoints too — we only tested the page you gave us."], snippets: [] },
      })];
    }
    if (c.acao === "null") {
      return [makeFinding({ ruleId: this.id, title: "CORS allows the 'null' origin", category: CAT, severity: creds ? "high" : "medium", confidence: "medium", status: "fail", affectedUrl: url, references: refs,
        summary: "Access-Control-Allow-Origin: null is set.", explanation: "Sandboxed iframes and local files send Origin: null, so any attacker can obtain it and read the response.", evidence: ev,
        remediation: { summary: "Remove Access-Control-Allow-Origin: null and list explicit trusted origins instead.", snippets: [] } })];
    }
    if (c.acao === "*") {
      if (creds) {
        return [makeFinding({ ruleId: this.id, title: "CORS combines wildcard origin with credentials", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
          summary: "Access-Control-Allow-Origin: * together with Allow-Credentials: true is an invalid combination.", explanation: "Browsers reject it, so cross-origin requests that need cookies silently fail — usually a sign of a misconfiguration.", evidence: ev,
          remediation: { summary: "Either drop credentials or replace * with a specific trusted origin.", snippets: [] } })];
      }
      return [makeFinding({ ruleId: this.id, title: "CORS allows all origins (public)", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url, references: refs,
        summary: "Any website may read this response (Access-Control-Allow-Origin: *).", explanation: "That's normal for public assets and open APIs, but make sure no private data is served with this header.", evidence: ev,
        remediation: { summary: "Keep * only for genuinely public resources.", snippets: [] } })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "CORS is restricted to a specific origin rather than reflecting ours.", explanation: "Unknown websites can't read responses.", evidence: ev, references: refs })];
  },
};

export const browserRules: Rule[] = [mixedContent, externalResources, cors];
