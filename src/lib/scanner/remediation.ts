import type { Platform, Remediation, Snippet } from "./types";

/**
 * Framework-specific fixes. Snippets are emitted ONLY for platforms the fingerprinter
 * positively detected. With no detection we return the header name/value and generic
 * steps — we never guess a configuration format for a stack we have not identified.
 */

const q = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

export function headerSnippets(name: string, value: string, platforms: Platform[]): Snippet[] {
  const out: Snippet[] = [];
  const has = (p: Platform) => platforms.includes(p);

  if (has("nextjs")) {
    out.push({
      platform: "nextjs",
      label: "Next.js — next.config.ts",
      language: "ts",
      code: `// next.config.ts
const nextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "${name}", value: "${q(value)}" }],
      },
    ];
  },
};
export default nextConfig;`,
    });
  }
  if (has("vercel")) {
    out.push({
      platform: "vercel",
      label: "Vercel — vercel.json",
      language: "json",
      code: JSON.stringify(
        { headers: [{ source: "/(.*)", headers: [{ key: name, value }] }] },
        null,
        2,
      ),
    });
  }
  if (has("cloudflare")) {
    out.push({
      platform: "cloudflare",
      label: "Cloudflare Pages / Workers static assets — _headers file",
      language: "text",
      code: `/*\n  ${name}: ${value}`,
    });
    out.push({
      platform: "cloudflare",
      label: "Cloudflare dashboard (proxied sites)",
      language: "text",
      code: `Rules → Transform Rules → Modify Response Header → Create rule\nWhen: All incoming requests\nThen: Set static   Header name: ${name}   Value: ${value}`,
    });
  }
  if (has("nginx")) {
    out.push({
      platform: "nginx",
      label: "Nginx — server block",
      language: "nginx",
      code: `add_header ${name} "${q(value)}" always;\n# then: nginx -t && sudo systemctl reload nginx`,
    });
  }
  if (has("apache")) {
    out.push({
      platform: "apache",
      label: "Apache — .htaccess or vhost (requires mod_headers)",
      language: "apache",
      code: `Header always set ${name} "${q(value)}"`,
    });
  }
  if (has("express")) {
    out.push({
      platform: "express",
      label: "Node.js / Express",
      language: "js",
      code: `app.use((req, res, next) => {\n  res.setHeader("${name}", "${q(value)}");\n  next();\n});\n// or use helmet: https://helmetjs.github.io/`,
    });
  }
  return out;
}

export function headerFix(name: string, value: string, platforms: Platform[], summary?: string): Remediation {
  const snippets = headerSnippets(name, value, platforms);
  if (snippets.length === 0) {
    return {
      summary: summary ?? `Send the response header ${name}: ${value}`,
      steps: [
        `Add this response header on your web server, CDN or hosting platform: ${name}: ${value}`,
        "We couldn't confidently identify your hosting stack, so we're not guessing a configuration file format.",
      ],
      snippets: [{ platform: "generic", label: "Header to add", language: "http", code: `${name}: ${value}` }],
      platformUnknown: true,
    };
  }
  return { summary: summary ?? `Send the response header ${name}: ${value}`, snippets };
}

/** HTTP → HTTPS redirect fix. */
export function httpsRedirectFix(platforms: Platform[]): Remediation {
  const snippets: Snippet[] = [];
  if (platforms.includes("vercel")) {
    snippets.push({
      platform: "vercel",
      label: "Vercel",
      language: "text",
      code: "Vercel redirects HTTP to HTTPS automatically on *.vercel.app and on custom domains added in Project → Settings → Domains. Check the domain is attached to the project and not proxied through another service that serves plain HTTP.",
    });
  }
  if (platforms.includes("cloudflare")) {
    snippets.push({
      platform: "cloudflare",
      label: "Cloudflare dashboard",
      language: "text",
      code: "SSL/TLS → Edge Certificates → turn on “Always Use HTTPS”.",
    });
  }
  if (platforms.includes("nginx")) {
    snippets.push({
      platform: "nginx",
      label: "Nginx",
      language: "nginx",
      code: `server {\n  listen 80;\n  server_name example.com www.example.com;\n  return 301 https://$host$request_uri;\n}`,
    });
  }
  if (platforms.includes("apache")) {
    snippets.push({
      platform: "apache",
      label: "Apache",
      language: "apache",
      code: `RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`,
    });
  }
  if (platforms.includes("express")) {
    snippets.push({
      platform: "express",
      label: "Node.js / Express (behind a proxy)",
      language: "js",
      code: `app.set("trust proxy", 1);\napp.use((req, res, next) =>\n  req.secure ? next() : res.redirect(301, "https://" + req.headers.host + req.originalUrl));`,
    });
  }
  if (snippets.length === 0) {
    return {
      summary: "Redirect every http:// request to the same URL on https:// with a permanent (301/308) redirect.",
      steps: [
        "Configure your web server, CDN or host to answer on port 80 with a 301 redirect to the https:// version of the same URL.",
        "We couldn't confidently identify your hosting stack, so we're not guessing a configuration file format.",
      ],
      snippets: [],
      platformUnknown: true,
    };
  }
  return { summary: "Redirect every http:// request to the same URL on https:// with a permanent (301/308) redirect.", snippets };
}

export function cookieFix(platforms: Platform[], flags: string[]): Remediation {
  const snippets: Snippet[] = [];
  if (platforms.includes("nextjs")) {
    snippets.push({
      platform: "nextjs",
      label: "Next.js — setting a cookie",
      language: "ts",
      code: `import { cookies } from "next/headers";\n\nconst jar = await cookies();\njar.set("session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });`,
    });
  }
  if (platforms.includes("express")) {
    snippets.push({
      platform: "express",
      label: "Node.js / Express",
      language: "js",
      code: `res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });`,
    });
  }
  return {
    summary: `Set ${flags.join(", ")} on the cookie where your application issues it.`,
    steps: [
      "Cookies are created by your application code or your auth library, so the fix is in the place that calls Set-Cookie.",
      "Secure: only sent over HTTPS. HttpOnly: JavaScript can't read it. SameSite=Lax (or Strict): limits cross-site sending.",
      ...(snippets.length ? [] : ["We couldn't identify your framework, so no code snippet is shown."]),
    ],
    snippets,
    platformUnknown: snippets.length === 0,
  };
}

/** Recommended values, shared between rules and tests. */
export const RECOMMENDED = {
  hsts: "max-age=63072000; includeSubDomains",
  xcto: "nosniff",
  xfo: "DENY",
  referrer: "strict-origin-when-cross-origin",
  permissions: "camera=(), microphone=(), geolocation=()",
  csp: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
} as const;
