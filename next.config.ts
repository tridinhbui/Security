import { readFileSync } from "node:fs";
import { initOpenNextCloudflareForDev } from "@opennextjs/cloudflare";
import type { NextConfig } from "next";

// `next dev` does not expose .dev.vars on process.env (the built Worker does), so load it for local development.
if (process.env.NODE_ENV !== "production") {
  try {
    for (const line of readFileSync(".dev.vars", "utf8").split("\n")) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !line.trim().startsWith("#") && process.env[m[1]!] === undefined) process.env[m[1]!] = m[2]!.replace(/^["']|["']$/g, "");
    }
  } catch { /* no .dev.vars: fine */ }
}

// Gives `next dev` access to local D1/Queues bindings from wrangler.jsonc.
initOpenNextCloudflareForDev();

const isDev = process.env.NODE_ENV !== "production";
const turnstile = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

// Security headers for VibeSec itself — we should pass our own audit.
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}${turnstile ? " https://challenges.cloudflare.com" : ""}`, // inline: Next.js bootstrap (nonces via proxy.ts would tighten this); eval: React dev tooling only
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https://*.googleusercontent.com", // ảnh đại diện Google
      "font-src 'self'",
      `connect-src 'self'${isDev ? " ws:" : ""}`,
      ...(turnstile ? ["frame-src https://challenges.cloudflare.com"] : []),
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; "),
  },
];

// Dấu vết bản dựng, được nhúng lúc build (Workers Builds đặt WORKERS_CI_COMMIT_SHA; GitHub Actions đặt GITHUB_SHA). Không bí mật.
const buildSha = process.env.WORKERS_CI_COMMIT_SHA ?? process.env.GITHUB_SHA ?? "unknown";

const config: NextConfig = {
  env: { BUILD_COMMIT_SHA: buildSha, BUILD_TIME: new Date().toISOString() },
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default config;
