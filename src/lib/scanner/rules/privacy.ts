import { getDomain } from "tldts";
import { headerFix, RECOMMENDED } from "../remediation";
import type { Rule } from "../types";
import { header, headerEvidence, isHtml, livePage, makeFinding, MDN, pass } from "../util";

const CAT = "Privacy" as const;

const referrerPolicy: Rule = {
  id: "privacy.referrer-policy",
  title: "Referrer-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const v = (header(p.headers, "referrer-policy") ?? obs.html?.metaReferrer ?? "").toLowerCase();
    const refs = [MDN("Web/HTTP/Reference/Headers/Referrer-Policy", "MDN: Referrer-Policy")];
    if (!v) {
      return [makeFinding({ ruleId: this.id, title: "Referrer-Policy is not set", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: "No Referrer-Policy header was sent.", explanation: "When visitors click links to other sites, their browser may tell those sites which page of yours they came from — including URLs that contain private tokens or IDs. Modern browsers default to a safe policy, but older ones don't.",
        evidence: [headerEvidence(p.headers, "referrer-policy")], remediation: headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms) })];
    }
    if (/\b(unsafe-url|no-referrer-when-downgrade)\b/.test(v)) {
      return [makeFinding({ ruleId: this.id, title: "Referrer-Policy leaks full URLs", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Referrer-Policy "${v}" sends full page URLs to other sites.`, explanation: "Full URLs (with paths and query strings) are shared with every third party you link to or load resources from.",
        evidence: [headerEvidence(p.headers, "referrer-policy")], remediation: headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms) })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "A privacy-preserving Referrer-Policy is set.", explanation: "Other sites learn little about where visitors came from.", evidence: [`Referrer-Policy: ${v}`], references: refs })];
  },
};

const permissionsPolicy: Rule = {
  id: "privacy.permissions-policy",
  title: "Permissions-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const v = header(p.headers, "permissions-policy");
    const refs = [MDN("Web/HTTP/Reference/Headers/Permissions-Policy", "MDN: Permissions-Policy")];
    if (v) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Browser features are explicitly restricted.", explanation: "Embedded content can't quietly use the camera, microphone or location.", evidence: [headerEvidence(p.headers, "permissions-policy")], references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Permissions-Policy is not set", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: p.finalUrl, references: refs,
      summary: "The site doesn't restrict powerful browser features for itself and embedded content.", explanation: "Optional hardening: it stops third-party scripts or frames from using the camera, microphone or location even if they try.",
      evidence: [headerEvidence(p.headers, "permissions-policy")], remediation: headerFix("Permissions-Policy", RECOMMENDED.permissions, obs.platforms) })];
  },
};

const thirdParties: Rule = {
  id: "privacy.third-party-origins",
  title: "Third-party requests",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const self = getDomain(new URL(obs.page.finalUrl).hostname);
    const hosts = new Set<string>();
    for (const r of obs.html.resources) {
      try {
        const h = new URL(r.url).hostname;
        if (getDomain(h) !== self) hosts.add(h);
      } catch { /* skip */ }
    }
    if (hosts.size === 0) return [pass({ ruleId: this.id, title: "No third-party resources on the page", category: CAT, affectedUrl: obs.page.finalUrl, summary: "The page loads everything from its own domain.", explanation: "Visitors' IP addresses and browsing aren't shared with other companies by this page.", evidence: [] })];
    return [makeFinding({ ruleId: this.id, title: "Page loads resources from third parties", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `${hosts.size} external host(s) receive visitors' IP address and browser details.`, explanation: "Each third-party script or asset is a privacy consideration (consent, disclosure) and a supply-chain risk. Keep only what you need.",
      technical: "Distinct hosts referenced by script/link/img/iframe/media tags on the page (homepage HTML only).", evidence: [...hosts].sort().slice(0, 20),
      remediation: { summary: "Review the list, remove unneeded integrations, self-host static assets, and disclose the rest in your privacy policy.", snippets: [] } })];
  },
};

export const privacyRules: Rule[] = [referrerPolicy, permissionsPolicy, thirdParties];
