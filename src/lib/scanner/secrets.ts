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
  return `${head}…(${value.length} ký tự)`;
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
    id: "private-key", label: "Khoá riêng tư (private key)", severity: "critical", confidence: "high",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    note: "Phần đầu của khoá riêng tư (PEM) xuất hiện trong nội dung công khai.",
  },
  {
    id: "aws-secret-pair", label: "AWS access key kèm secret key", severity: "critical", confidence: "high",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b[\s\S]{0,120}?['"][A-Za-z0-9/+=]{40}['"]/g,
    note: "Một AWS access key ID xuất hiện cạnh chuỗi 40 ký tự trông giống khoá bí mật.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "aws-access-key-id", label: "AWS access key ID", severity: "medium", confidence: "medium",
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    note: "AWS access key ID chỉ là mã định danh, chưa phải bí mật, nhưng không nên đưa xuống trình duyệt.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "stripe-live-secret", label: "Khoá bí mật Stripe (live)", severity: "critical", confidence: "high",
    re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g,
    note: "Khoá Stripe live (secret/restricted) cấp quyền gọi API vào tài khoản Stripe của bạn.",
  },
  {
    id: "stripe-test-secret", label: "Khoá bí mật Stripe (test)", severity: "low", confidence: "high",
    re: /\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b/g,
    note: "Khoá bí mật Stripe chế độ thử nghiệm. Rủi ro thấp hơn (không có tiền thật) nhưng vẫn không bao giờ nên công khai.",
  },
  {
    id: "github-token", label: "Token GitHub", severity: "critical", confidence: "high",
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
    note: "Token GitHub (cá nhân/OAuth/ứng dụng) có thể truy cập kho mã nguồn.",
  },
  {
    id: "slack-token", label: "Token Slack", severity: "high", confidence: "high",
    re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    note: "Token Slack có thể đọc hoặc đăng tin nhắn.",
    accept: (m) => !PLACEHOLDER.test(m),
  },
  {
    id: "slack-webhook", label: "Webhook Slack", severity: "medium", confidence: "high",
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g,
    note: "Bất kỳ ai có URL này đều đăng được tin nhắn vào kênh Slack của bạn.",
  },
  {
    id: "sendgrid-key", label: "Khoá API SendGrid", severity: "critical", confidence: "high",
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    note: "Khoá SendGrid cho phép gửi email mạo danh tên miền của bạn.",
  },
  {
    id: "openai-key", label: "Khoá API OpenAI", severity: "critical", confidence: "high",
    re: /\b(?:sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{48})\b/g,
    note: "Khoá API LLM bị lộ rất nhanh bị lạm dụng và chi phí do bạn chịu.",
  },
  {
    id: "anthropic-key", label: "Khoá API Anthropic", severity: "critical", confidence: "high",
    re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{60,}\b/g,
    note: "Khoá API LLM bị lộ rất nhanh bị lạm dụng và chi phí do bạn chịu.",
  },
  {
    id: "npm-token", label: "Token truy cập npm", severity: "critical", confidence: "high",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    note: "Token npm có thể đăng gói phần mềm dưới danh nghĩa của bạn.",
  },
  {
    id: "db-url-with-password", label: "URL cơ sở dữ liệu chứa mật khẩu", severity: "critical", confidence: "high",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/'"`\\]{1,64}:([^\s@/'"`\\]{4,})@[^\s'"`\\]{3,}/g,
    note: "Chuỗi kết nối cơ sở dữ liệu có chứa mật khẩu đang hiển thị công khai.",
    accept: (m) => !PLACEHOLDER.test(m) && !/localhost|127\.0\.0\.1/.test(m),
  },
  {
    id: "google-api-key", label: "Khoá Google API", severity: "info", confidence: "high", publicByDesign: true,
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    note: "Khoá Google API cho trình duyệt được thiết kế để công khai, nhưng cần giới hạn theo HTTP referrer và theo API.",
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
        id: "supabase-service-role", label: "Khoá Supabase service_role", severity: "critical", confidence: "high",
        redacted: redact(m[0]),
        note: "JWT có role=service_role bỏ qua toàn bộ Row Level Security. Khoá này chỉ được tồn tại trên máy chủ.",
      });
    } else if (role === "anon" && (iss.includes("supabase") || "ref" in payload)) {
      push({
        id: "supabase-anon-key", label: "Khoá Supabase anon", severity: "info", confidence: "high", publicByDesign: true,
        redacted: redact(m[0]),
        note: "Khoá anon được thiết kế để công khai — an toàn của bạn phụ thuộc vào việc bật Row Level Security trên mọi bảng.",
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
