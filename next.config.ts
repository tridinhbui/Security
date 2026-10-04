import { initOpenNextCloudflareForDev } from "@opennextjs/cloudflare";
import type { NextConfig } from "next";

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
      "img-src 'self' data:",
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

const config: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default config;
