import type { Platform, Remediation, Snippet } from "./types";

/**
 * Hướng dẫn khắc phục theo nền tảng. Đoạn cấu hình CHỈ được đưa ra cho nền tảng mà bộ nhận diện
 * xác định chắc chắn. Nếu không nhận diện được, chúng tôi chỉ đưa tên/giá trị header và các bước chung —
 * không bao giờ đoán định dạng file cấu hình cho một hệ thống chưa xác định.
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
      label: "Cloudflare Pages / Workers (tài nguyên tĩnh) — file _headers",
      language: "text",
      code: `/*\n  ${name}: ${value}`,
    });
    out.push({
      platform: "cloudflare",
      label: "Bảng điều khiển Cloudflare (website đi qua proxy Cloudflare)",
      language: "text",
      code: `Rules → Transform Rules → Modify Response Header → Create rule\nKhi (When): All incoming requests\nThì (Then): Set static   Header name: ${name}   Value: ${value}`,
    });
  }
  if (has("nginx")) {
    out.push({
      platform: "nginx",
      label: "Nginx — trong khối server",
      language: "nginx",
      code: `add_header ${name} "${q(value)}" always;\n# sau đó: nginx -t && sudo systemctl reload nginx`,
    });
  }
  if (has("apache")) {
    out.push({
      platform: "apache",
      label: "Apache — .htaccess hoặc vhost (cần mod_headers)",
      language: "apache",
      code: `Header always set ${name} "${q(value)}"`,
    });
  }
  if (has("express")) {
    out.push({
      platform: "express",
      label: "Node.js / Express",
      language: "js",
      code: `app.use((req, res, next) => {\n  res.setHeader("${name}", "${q(value)}");\n  next();\n});\n// hoặc dùng thư viện helmet: https://helmetjs.github.io/`,
    });
  }
  return out;
}

export function headerFix(name: string, value: string, platforms: Platform[], summary?: string): Remediation {
  const snippets = headerSnippets(name, value, platforms);
  if (snippets.length === 0) {
    return {
      summary: summary ?? `Gửi header phản hồi ${name}: ${value}`,
      steps: [
        `Thêm header phản hồi sau trên máy chủ web, CDN hoặc nền tảng hosting của bạn: ${name}: ${value}`,
        "Chúng tôi không xác định chắc chắn được hệ thống hosting của bạn nên không đoán định dạng file cấu hình.",
      ],
      snippets: [{ platform: "generic", label: "Header cần thêm", language: "http", code: `${name}: ${value}` }],
      platformUnknown: true,
    };
  }
  return { summary: summary ?? `Gửi header phản hồi ${name}: ${value}`, snippets };
}

/** Khắc phục chuyển hướng HTTP → HTTPS. */
export function httpsRedirectFix(platforms: Platform[]): Remediation {
  const snippets: Snippet[] = [];
  if (platforms.includes("vercel")) {
    snippets.push({
      platform: "vercel",
      label: "Vercel",
      language: "text",
      code: "Vercel tự động chuyển HTTP sang HTTPS cho *.vercel.app và các tên miền riêng được thêm ở Project → Settings → Domains. Hãy kiểm tra tên miền đã gắn vào project và không đi qua một dịch vụ proxy khác đang phục vụ HTTP thuần.",
    });
  }
  if (platforms.includes("cloudflare")) {
    snippets.push({
      platform: "cloudflare",
      label: "Bảng điều khiển Cloudflare",
      language: "text",
      code: "SSL/TLS → Edge Certificates → bật “Always Use HTTPS”.",
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
      label: "Node.js / Express (phía sau proxy)",
      language: "js",
      code: `app.set("trust proxy", 1);\napp.use((req, res, next) =>\n  req.secure ? next() : res.redirect(301, "https://" + req.headers.host + req.originalUrl));`,
    });
  }
  if (snippets.length === 0) {
    return {
      summary: "Chuyển hướng mọi request http:// sang cùng URL đó trên https:// bằng chuyển hướng vĩnh viễn (301/308).",
      steps: [
        "Cấu hình máy chủ web, CDN hoặc nhà cung cấp hosting để cổng 80 trả về chuyển hướng 301 tới phiên bản https:// của cùng URL.",
        "Chúng tôi không xác định chắc chắn được hệ thống hosting của bạn nên không đoán định dạng file cấu hình.",
      ],
      snippets: [],
      platformUnknown: true,
    };
  }
  return { summary: "Chuyển hướng mọi request http:// sang cùng URL đó trên https:// bằng chuyển hướng vĩnh viễn (301/308).", snippets };
}

export function cookieFix(platforms: Platform[], flags: string[]): Remediation {
  const snippets: Snippet[] = [];
  if (platforms.includes("nextjs")) {
    snippets.push({
      platform: "nextjs",
      label: "Next.js — khi đặt cookie",
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
    summary: `Đặt ${flags.join(", ")} cho cookie tại nơi ứng dụng của bạn tạo ra nó.`,
    steps: [
      "Cookie được tạo bởi mã ứng dụng hoặc thư viện đăng nhập của bạn, nên cần sửa đúng chỗ gọi Set-Cookie.",
      "Secure: chỉ gửi qua HTTPS. HttpOnly: JavaScript không đọc được cookie. SameSite=Lax (hoặc Strict): hạn chế gửi cookie từ trang khác.",
      ...(snippets.length ? [] : ["Chúng tôi không nhận diện được framework của bạn nên không hiển thị đoạn mã mẫu."]),
    ],
    snippets,
    platformUnknown: snippets.length === 0,
  };
}

/** Giá trị khuyến nghị, dùng chung cho các luật và test. */
export const RECOMMENDED = {
  hsts: "max-age=63072000; includeSubDomains",
  xcto: "nosniff",
  xfo: "DENY",
  referrer: "strict-origin-when-cross-origin",
  permissions: "camera=(), microphone=(), geolocation=()",
  csp: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
} as const;
