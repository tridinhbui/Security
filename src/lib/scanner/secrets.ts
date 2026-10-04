import type { Severity, Confidence } from "./types";

/**
 * Conservative secret detection for content that is ALREADY public (HTML/JS served to
 * everyone). Only provider-specific, high-structure formats — no generic "looks like a
 * password" heuristics, which are false-positive machines. Matches are redacted at the
 * moment of detection; the raw value never leaves this module.
 */

export interface SecretMatch {
  id: string;
  label: string;
  severity: Severity;
  confidence: Confidence;
  /** e.g. "AKIA…(20 chars)" — never the full value. */
  redacted: string;
  note: string;
  /** Info-only "public by design" matches (anon keys, Google API keys). */
  publicByDesign?: boolean;
}

interface Pattern {
  id: string;
  label: string;
  re: RegExp;
  severity: Severity;
  confidence: Confidence;
  note: string;
  publicByDesign?: boolean;
  /** Extra validation to cut false positives. */
  accept?: (m: string, context: string) => boolean;
}

export function redact(value: string): string {
  const head = value.slice(0, Math.min(4, Math.floor(value.length / 4)));
  return `${head}…(${value.length} chars)`;
}

const PLACEHOLDER = /(example|placeholder|your[_-]?|xxxx|\*{4,}|<[^>]+>|changeme|dummy|sample|test1234)/i;

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const obj = JSON.parse(json);
    return obj && typeof obj === "object" ? obj : null;
  } catch {
    return null;
  }
}

const PATTERNS: Pattern[] = [
  {
    id: "private-key", label: "Private key block", severity: "critical", confidence: "high",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    note: "A PEM private key header appears in publicly served content.",
  },
  {
    id: "aws-secret-pair", label: "AWS access key with secret key", severity: "critical", confidence: "high",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b[\s\S]{0,120}?['"][A-Za-z0-9/+=]{40}['"]/g,
    note: "An AWS access key ID appears next to a 40-character secret-looking value.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "aws-access-key-id", label: "AWS access key ID", severity: "medium", confidence: "medium",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    note: "AWS access key IDs are identifiers, not secrets by themselves, but should not be shipped to browsers.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "stripe-live-secret", label: "Stripe live secret key", severity: "critical", confidence: "high",
    re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g,
    note: "Stripe live secret/restricted keys grant API access to your Stripe account.",
  },
  {
    id: "stripe-test-secret", label: "Stripe test secret key", severity: "low", confidence: "high",
    re: /\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b/g,
    note: "A Stripe test-mode secret key. Lower risk (no real money) but it should still never be public.",
  },
  {
    id: "github-token", label: "GitHub token", severity: "critical", confidence: "high",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
    note: "GitHub personal/OAuth/app tokens can access repositories.",
  },
  {
    id: "slack-token", label: "Slack token", severity: "high", confidence: "high",
    re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    note: "Slack API tokens can read or post messages.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "slack-webhook", label: "Slack incoming webhook URL", severity: "medium", confidence: "high",
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g,
    note: "Anyone with this URL can post to your Slack channel.",
  },
  {
    id: "sendgrid-key", label: "SendGrid API key", severity: "critical", confidence: "high",
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    note: "SendGrid keys allow sending email as your domain.",
  },
  {
    id: "openai-key", label: "OpenAI API key", severity: "critical", confidence: "high",
    re: /\b(?:sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{48})\b/g,
    note: "Exposed LLM API keys are quickly abused and billed to you.",
  },
  {
    id: "anthropic-key", label: "Anthropic API key", severity: "critical", confidence: "high",
    re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{60,}\b/g,
    note: "Exposed LLM API keys are quickly abused and billed to you.",
  },
  {
    id: "npm-token", label: "npm access token", severity: "critical", confidence: "high",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    note: "npm tokens can publish packages as you.",
  },
  {
    id: "db-url-with-password", label: "Database URL containing a password", severity: "critical", confidence: "high",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/'"`\\]{1,64}:([^\s@/'"`\\]{4,})@[^\s'"`\\]{3,}/g,
    note: "A connection string with embedded credentials is publicly readable.",
    accept: (m) => !PLACEHOLDER.test(m) && !/localhost|127\.0\.0\.1/.test(m),
  },
  {
    id: "google-api-key", label: "Google API key", severity: "info", confidence: "high", publicByDesign: true,
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    note: "Google API keys for browser use are designed to be public, but should be restricted by HTTP referrer and API.",
  },
];

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

/** Scan text for secrets; returns redacted matches, deduplicated by (id, redacted). */
export function detectSecrets(text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  const seen = new Set<string>();
  const push = (m: SecretMatch) => {
    const k = `${m.id}:${m.redacted}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(m);
    }
  };

  const covered: Array<[number, number]> = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      const value = m[0];
      const idx = m.index ?? 0;
      if (p.accept && !p.accept(value, text.slice(Math.max(0, idx - 40), idx + value.length + 40))) continue;
      // A higher-severity pattern that already covered this span suppresses weaker duplicates.
      if (covered.some(([a, b]) => idx >= a && idx < b)) continue;
      covered.push([idx, idx + value.length]);
      push({ id: p.id, label: p.label, severity: p.severity, confidence: p.confidence, redacted: redact(value), note: p.note, publicByDesign: p.publicByDesign });
    }
  }

  for (const m of text.matchAll(JWT_RE)) {
    const payload = decodeJwtPayload(m[0]);
    if (!payload) continue;
    const iss = String(payload.iss ?? "");
    const role = String(payload.role ?? "");
    if (role === "service_role") {
      push({
        id: "supabase-service-role", label: "Supabase service_role key", severity: "critical", confidence: "high",
        redacted: redact(m[0]),
        note: "A JWT with role=service_role bypasses all Row Level Security. It must only ever exist on a server.",
      });
    } else if (role === "anon" && (iss.includes("supabase") || "ref" in payload)) {
      push({
        id: "supabase-anon-key", label: "Supabase anon key", severity: "info", confidence: "high", publicByDesign: true,
        redacted: redact(m[0]),
        note: "The anon key is meant to be public — your security depends on Row Level Security policies being enabled on every table.",
      });
    }
  }
  return out;
}

// ------------------------------------------------------------------ public client config

export interface PublicConfigEntry {
  key: string;
  valueLength: number;
  sensitiveName: boolean;
}

const CLIENT_PREFIXES = /^(?:NEXT_PUBLIC|REACT_APP|VITE|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]{2,}$/;
const SENSITIVE_NAME = /(SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|CLIENT_SECRET|ACCESS_TOKEN|SIGNING_KEY|WEBHOOK_SECRET)/;

/**
 * Finds `"NEXT_PUBLIC_FOO":"value"` / `NEXT_PUBLIC_FOO: 'value'` style pairs — i.e. environment
 * values the build deliberately inlined into public JS. Values are measured, never kept.
 */
export function detectPublicConfig(text: string): PublicConfigEntry[] {
  const re = /["']?((?:NEXT_PUBLIC|REACT_APP|VITE|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]{2,})["']?\s*[:=]\s*(?:"([^"\n]{1,2000})"|'([^'\n]{1,2000})')/g;
  const found = new Map<string, PublicConfigEntry>();
  for (const m of text.matchAll(re)) {
    const key = m[1]!;
    const value = m[2] ?? m[3] ?? "";
    if (!CLIENT_PREFIXES.test(key) || value.length < 1) continue;
    found.set(key, { key, valueLength: value.length, sensitiveName: SENSITIVE_NAME.test(key) && value.length >= 8 && !PLACEHOLDER.test(value) });
  }
  return [...found.values()].slice(0, 60);
}
