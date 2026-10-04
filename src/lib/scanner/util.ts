import type { Headers } from "../ssrf/types";
import type { Category, Confidence, Finding, FindingStatus, Observations, Reference, Remediation, Severity } from "./types";

export function header(h: Headers | undefined, name: string): string | undefined {
  const v = h?.[name.toLowerCase()];
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v.join(", ") : v;
}

export function setCookies(h: Headers | undefined): string[] {
  const v = h?.["set-cookie"];
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

/** Evidence line for a header, or "(header not present)". Truncated to keep reports small. */
export function headerEvidence(h: Headers | undefined, name: string): string {
  const v = header(h, name);
  return v === undefined ? `${name}: (not present)` : `${name}: ${truncate(v, 300)}`;
}

export function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function pathOf(url: string | null | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}

export interface FindingInput {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  summary: string;
  explanation: string;
  technical?: string;
  evidence?: string[];
  remediation?: Remediation | null;
  affectedUrl?: string | null;
  references?: Reference[];
  /** Extra discriminator when one rule emits several findings. */
  key?: string;
}

export function makeFinding(i: FindingInput): Finding {
  return {
    ruleId: i.ruleId,
    title: i.title,
    category: i.category,
    severity: i.severity,
    confidence: i.confidence,
    status: i.status,
    summary: i.summary,
    explanation: i.explanation,
    technical: i.technical,
    evidence: i.evidence ?? [],
    remediation: i.remediation ?? null,
    affectedUrl: i.affectedUrl ?? null,
    references: i.references ?? [],
    fingerprint: `${i.ruleId}|${i.key ?? pathOf(i.affectedUrl)}`,
  };
}

/** A passing check (shown in the report as "what's already good"). */
export function pass(i: Omit<FindingInput, "status" | "severity" | "confidence"> & { confidence?: Confidence }): Finding {
  return makeFinding({ ...i, status: "pass", severity: "info", confidence: i.confidence ?? "high" });
}

export const MDN = (path: string, title: string): Reference => ({
  title,
  url: `https://developer.mozilla.org/en-US/docs/${path}`,
});
export const OWASP = (path: string, title: string): Reference => ({
  title,
  url: `https://cheatsheetseries.owasp.org/cheatsheets/${path}`,
});

/** The https page record only if it loaded; many rules apply to the live HTTPS page. */
export function livePage(obs: Observations) {
  return obs.page && !obs.page.error && obs.page.status !== null ? obs.page : null;
}

/** Reasonable test for "this looks like an HTML document" (avoid analysing JSON/redirect stubs). */
export function isHtml(contentType: string): boolean {
  return contentType.includes("text/html") || contentType.includes("application/xhtml");
}
