import type { Reference } from "./types";

/**
 * TẦNG 2 — "Đào sâu kỹ thuật" cho các phát hiện phổ biến và quan trọng nhất.
 * Tầng 1 (giải thích cho người mới) nằm ở explain.ts / explain-more.ts / feynman.ts và KHÔNG bị thay đổi ở đây.
 *
 * Quy ước (được khoá bằng src/lib/scanner/__tests__/deep-dive.test.ts):
 *  - `kind` phân biệt: lỗi cấu hình đã quan sát được · khuyến nghị thực hành tốt · chưa đủ bằng chứng để gọi là lỗi;
 *  - `examples` là cấu hình header mẫu: test áp chúng vào website mẫu và chạy lại CHÍNH các luật quét để chắc chắn
 *    mẫu không tạo ra phát hiện mới (không có "mẫu sửa lỗi này nhưng gây lỗi khác");
 *  - `verify` chỉ gồm lệnh CHỈ ĐỌC; `sources` chỉ dùng tài liệu chính thống (MDN, RFC, OWASP, tài liệu nền tảng).
 */
export type DiveKind = "misconfiguration" | "best-practice" | "needs-evidence";
export const KIND_LABEL: Record<DiveKind, { label: string; hint: string }> = {
  misconfiguration: { label: "Cấu hình sai (đã quan sát được)", hint: "Chúng tôi thấy trực tiếp cấu hình đang sai hoặc thiếu; chưa chứng minh có ai khai thác." },
  "best-practice": { label: "Khuyến nghị thực hành tốt", hint: "Không phải lỗi trực tiếp; là lớp phòng thủ nên có. Thiếu nó không có nghĩa website đang bị tấn công." },
  "needs-evidence": { label: "Dấu hiệu, chưa đủ bằng chứng", hint: "Quét thụ động chỉ thấy dấu hiệu. Cần con người xác minh trước khi coi là lỗ hổng." },
};
export type DivePlatform = "nextjs" | "vercel" | "cloudflare" | "supabase" | "nginx" | "generic";
export const PLATFORM_LABEL: Record<DivePlatform, string> = {
  nextjs: "Next.js", vercel: "Vercel", cloudflare: "Cloudflare (Workers / CDN)", supabase: "Supabase", nginx: "Nginx", generic: "Chung",
};
export interface DiveSnippet { platform: DivePlatform; label: string; language: string; code: string }
export interface DeepDive {
  kind: DiveKind;
  /** Cơ chế hoạt động, viết cho người đọc kỹ thuật. */
  mechanism: string;
  /** Ví dụ trao đổi HTTP trước/sau khi sửa. */
  exchange?: { before: string; after: string };
  /** Header mẫu được test tự động (ghi đè lên website mẫu đã cứng hoá). */
  examples?: { name: string; value: string; /** Luật kiểm tra riêng cho mẫu này (mặc định: `checks` của mục). */ checks?: string[]; /** Luật khuyến nghị nâng cao được phép còn lại (mẫu chưa đạt mức cao nhất nhưng không sai). */ allow?: string[] }[];
  /** Các luật phải KHÔNG báo lỗi sau khi áp `examples`. */
  checks?: string[];
  frameworks: DiveSnippet[];
  mistakes: string[];
  tradeoffs: string[];
  verify: string[];
  sources: Reference[];
}

const L = (...lines: string[]) => lines.join("\n");
const S = (platform: DivePlatform, label: string, language: string, code: string): DiveSnippet => ({ platform, label, language, code });
const R = (title: string, url: string): Reference => ({ title, url });
const MDN = (path: string, title: string) => R(title, `https://developer.mozilla.org/en-US/docs/${path}`);
const OWASP_CS = (page: string, title: string) => R(title, `https://cheatsheetseries.owasp.org/cheatsheets/${page}.html`);

/** Một header gửi qua next.config.ts (Next.js, App Router). */
const nextHeader = (name: string, value: string) => S("nextjs", "next.config.ts — headers()", "ts", L(
  "// next.config.ts",
  "import type { NextConfig } from \"next\";",
  "",
  "const nextConfig: NextConfig = {",
  "  async headers() {",
  "    return [{ source: \"/:path*\", headers: [{ key: \"" + name + "\", value: \"" + value + "\" }] }];",
  "  },",
  "};",
  "export default nextConfig;",
));
const vercelHeader = (name: string, value: string) => S("vercel", "vercel.json", "json", JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: name, value }] }] }, null, 2));
const cfStatic = (name: string, value: string) => S("cloudflare", "Cloudflare Workers — tài nguyên tĩnh: tệp public/_headers (KHÔNG áp cho phản hồi do mã Worker/Next tạo ra)", "text", L("/*", "  " + name + ": " + value));
const cfWorker = (name: string, value: string) => S("cloudflare", "Cloudflare Worker — đặt header trên phản hồi do bạn kiểm soát", "ts", L(
  "export default {",
  "  async fetch(request: Request, env: Env): Promise<Response> {",
  "    const upstream = await env.ASSETS.fetch(request); // hoặc phản hồi của ứng dụng",
  "    const res = new Response(upstream.body, upstream); // bản sao có thể sửa header",
  "    res.headers.set(\"" + name + "\", \"" + value + "\");",
  "    return res;",
  "  },",
  "} satisfies ExportedHandler<Env>;",
));
const headerEverywhere = (name: string, value: string): DiveSnippet[] => [nextHeader(name, value), vercelHeader(name, value), cfStatic(name, value), cfWorker(name, value)];

const CSP_NONCE = "default-src 'self'; script-src 'self' 'nonce-RANDOM' 'strict-dynamic'; style-src 'self' 'nonce-RANDOM'; img-src 'self' blob: data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";
const SIMPLE_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

const CSP_DIVE: DeepDive = {
  kind: "misconfiguration",
  mechanism: "CSP là một danh sách nguồn mà trình duyệt được phép tải/chạy (script, style, ảnh, iframe…). Khi có lỗi XSS, kẻ tấn công chèn được `<script>` vào trang; CSP chặt khiến trình duyệt từ chối chạy nó. CSP KHÔNG vá lỗi XSS, chỉ giảm tác hại: vì vậy 'unsafe-inline' (cho mọi script nội tuyến chạy) hay `*` (mọi host) làm CSP mất gần hết tác dụng. 'strict-dynamic' + nonce là mẫu hiện đại: chỉ script mang đúng nonce của request này (và script do chúng nạp) được chạy.",
  exchange: {
    before: L("GET / HTTP/2", "", "HTTP/2 200", "content-type: text/html; charset=utf-8", "(không có content-security-policy)"),
    after: L("GET / HTTP/2", "", "HTTP/2 200", "content-type: text/html; charset=utf-8", "content-security-policy: " + SIMPLE_CSP),
  },
  examples: [{ name: "content-security-policy", value: SIMPLE_CSP }, { name: "content-security-policy", value: CSP_NONCE.replace(/RANDOM/g, "dGhpcy1pcy1hLXRlc3Q=") }],
  checks: ["headers.csp", "adv.csp-analysis", "headers.broken"],
  frameworks: [
    S("nextjs", "Next.js 16 — nonce theo từng request trong proxy.ts (tên cũ middleware.ts ở Next ≤15). Trang phải render động.", "ts", L(
      "// proxy.ts",
      "import { NextRequest, NextResponse } from \"next/server\";",
      "",
      "export function proxy(request: NextRequest) {",
      "  const nonce = Buffer.from(crypto.randomUUID()).toString(\"base64\");",
      "  const csp = [",
      "    \"default-src 'self'\",",
      "    \"script-src 'self' 'nonce-\" + nonce + \"' 'strict-dynamic'\",",
      "    \"style-src 'self' 'nonce-\" + nonce + \"'\",",
      "    \"object-src 'none'\", \"base-uri 'self'\", \"form-action 'self'\", \"frame-ancestors 'none'\",",
      "  ].join(\"; \");",
      "  const requestHeaders = new Headers(request.headers);",
      "  requestHeaders.set(\"x-nonce\", nonce);",
      "  requestHeaders.set(\"Content-Security-Policy\", csp);",
      "  const response = NextResponse.next({ request: { headers: requestHeaders } });",
      "  response.headers.set(\"Content-Security-Policy\", csp);",
      "  return response;",
      "}",
    )),
    nextHeader("Content-Security-Policy-Report-Only", SIMPLE_CSP),
    vercelHeader("Content-Security-Policy-Report-Only", SIMPLE_CSP),
    cfStatic("Content-Security-Policy-Report-Only", SIMPLE_CSP),
  ],
  mistakes: [
    "Bật thẳng Content-Security-Policy cho website đang chạy: trang hỏng vì chặn nhầm script/ảnh hợp lệ. Hãy bắt đầu bằng Content-Security-Policy-Report-Only.",
    "Thêm 'unsafe-inline' cho “nhanh hết lỗi” trên console: việc đó vô hiệu hoá phần quan trọng nhất của CSP.",
    "Đặt CSP trong thẻ <meta>: frame-ancestors, report-uri và sandbox bị bỏ qua; nên dùng HTTP header.",
    "Nonce dùng lại giữa các request (hoặc nonce tĩnh trong HTML đã build/cache): kẻ tấn công đọc được nonce thì vô dụng. Nonce phải ngẫu nhiên MỖI request, nên trang không được cache tĩnh.",
    "Quên các nguồn thật sự cần (analytics, font, thanh toán) rồi gỡ CSP khi có sự cố thay vì thêm đúng nguồn.",
  ],
  tradeoffs: [
    "Nonce buộc render động ở Next.js nên mất cache tĩnh/CDN cho các trang đó; nếu cần tĩnh hoàn toàn, dùng hash hoặc bỏ 'unsafe-inline' bằng cách chuyển script nội tuyến ra tệp.",
    "style-src nghiêm ngặt có thể làm hỏng thư viện UI chèn style trong lúc chạy; một số thư viện vẫn cần 'unsafe-inline' cho style (rủi ro thấp hơn script).",
    "Tiện ích mở rộng trình duyệt của khách có thể sinh báo cáo vi phạm nhiễu; lọc khi đọc báo cáo.",
  ],
  verify: ["curl -sI https://example.com/ | grep -i content-security-policy", "Dán chính sách vào https://csp-evaluator.withgoogle.com/ để xem điểm yếu còn lại", "Mở DevTools → Console: không còn lỗi “Refused to load/execute…” cho tài nguyên hợp lệ"],
  sources: [MDN("Web/HTTP/CSP", "MDN: Content Security Policy"), OWASP_CS("Content_Security_Policy_Cheat_Sheet", "OWASP Cheat Sheet: Content Security Policy"), R("Next.js: Content Security Policy", "https://nextjs.org/docs/app/guides/content-security-policy"), R("W3C CSP Level 3", "https://www.w3.org/TR/CSP3/")],
};

const HSTS = "max-age=63072000; includeSubDomains";
const REFERRER = "strict-origin-when-cross-origin";
const XCTO = "nosniff";
const PERMS = "camera=(), microphone=(), geolocation=()";

export const DEEP_DIVE: Record<string, DeepDive> = {
  "headers.csp": CSP_DIVE,
  "adv.csp-analysis": { ...CSP_DIVE, kind: "misconfiguration" },

  "tls.hsts": {
    kind: "misconfiguration",
    mechanism: "HSTS (RFC 6797) là header mà trình duyệt chỉ chấp nhận khi nhận qua HTTPS. Sau đó, trong max-age giây, trình duyệt tự đổi mọi http:// tới tên miền này thành https:// TRƯỚC khi gửi đi, và không cho khách bấm bỏ qua cảnh báo chứng chỉ. Nó chặn SSL stripping, nhưng chỉ từ lần truy cập thứ hai; muốn bảo vệ cả lần đầu cần danh sách preload.",
    exchange: {
      before: L("GET / HTTP/2  (https://example.com)", "", "HTTP/2 200", "(không có strict-transport-security)"),
      after: L("GET / HTTP/2  (https://example.com)", "", "HTTP/2 200", "strict-transport-security: " + HSTS),
    },
    examples: [{ name: "strict-transport-security", value: HSTS, checks: ["tls.hsts", "headers.broken"], allow: ["tls.hsts-preload"] }, { name: "strict-transport-security", value: HSTS + "; preload", checks: ["tls.hsts", "tls.hsts-preload", "headers.broken"] }],
    checks: ["tls.hsts", "headers.broken"],
    frameworks: [
      ...headerEverywhere("Strict-Transport-Security", HSTS),
      S("cloudflare", "Cloudflare CDN (bảng điều khiển)", "text", "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) → Enable HSTS. Chọn Max-Age 12 tháng trở lên; chỉ bật “Apply HSTS policy to subdomains” khi mọi tên miền con chạy HTTPS."),
      S("nginx", "Nginx", "nginx", "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"),
    ],
    mistakes: [
      "Bật includeSubDomains khi còn một tên miền con chỉ chạy HTTP (ví dụ dịch vụ nội bộ, mail webmail cũ): các tên miền con đó sẽ không truy cập được.",
      "Đặt max-age rất lớn ngay từ đầu rồi phát hiện lỗi chứng chỉ: khách không thể bấm “tiếp tục” cho đến khi sửa. Hãy thử với max-age=300 trước, tăng dần.",
      "Gửi HSTS trên phản hồi HTTP: trình duyệt bỏ qua; header chỉ có tác dụng qua HTTPS.",
      "Thêm “preload” rồi gửi tên miền vào danh sách khi chưa chắc chắn: gỡ khỏi danh sách preload mất hàng tháng.",
    ],
    tradeoffs: [
      "HSTS là cam kết dài hạn: một khi trình duyệt đã nhớ, bạn không thể quay lại HTTP trong thời hạn max-age.",
      "Danh sách preload yêu cầu max-age ≥ 31536000 (1 năm), includeSubDomains và preload; việc đưa vào gần như một chiều.",
    ],
    verify: ["curl -sI https://example.com/ | grep -i strict-transport-security", "curl -sI http://example.com/ | head -3   # phải 301 sang https://", "Tra https://hstspreload.org/?domain=example.com nếu định preload"],
    sources: [MDN("Web/HTTP/Reference/Headers/Strict-Transport-Security", "MDN: Strict-Transport-Security"), R("RFC 6797: HTTP Strict Transport Security", "https://www.rfc-editor.org/rfc/rfc6797"), R("HSTS Preload List", "https://hstspreload.org/"), OWASP_CS("HTTP_Strict_Transport_Security_Cheat_Sheet", "OWASP Cheat Sheet: HSTS")],
  },

  "tls.http-to-https-redirect": {
    kind: "misconfiguration",
    mechanism: "Khách gõ `example.com` hoặc bấm liên kết cũ thường bắt đầu bằng http://. Nếu máy chủ trả 200 trên HTTP thay vì chuyển hướng, mọi thứ trong phiên đó đi không mã hoá. Chuyển hướng 301/308 đưa khách sang HTTPS; HSTS (mục riêng) giúp trình duyệt tự làm bước này từ lần sau.",
    exchange: {
      before: L("GET / HTTP/1.1", "Host: example.com   (cổng 80)", "", "HTTP/1.1 200 OK"),
      after: L("GET / HTTP/1.1", "Host: example.com   (cổng 80)", "", "HTTP/1.1 301 Moved Permanently", "Location: https://example.com/"),
    },
    frameworks: [
      S("cloudflare", "Cloudflare CDN", "text", "SSL/TLS → Edge Certificates → Always Use HTTPS = On. Dùng chế độ mã hoá Full (strict), không dùng Flexible."),
      S("vercel", "Vercel", "text", "Vercel tự chuyển HTTP sang HTTPS cho tên miền đã gắn; nếu vẫn thấy 200 trên http://, kiểm tra tên miền có đi qua proxy/CDN khác phía trước không."),
      S("nginx", "Nginx", "nginx", L("server {", "  listen 80;", "  server_name example.com www.example.com;", "  return 301 https://example.com$request_uri;", "}")),
    ],
    mistakes: [
      "Bật Always Use HTTPS nhưng để Cloudflare ở chế độ Flexible: Cloudflare nói chuyện HTTP với máy chủ gốc, máy chủ lại chuyển sang HTTPS → vòng lặp chuyển hướng vô hạn. Dùng Full (strict) và chứng chỉ hợp lệ ở máy chủ gốc.",
      "Dùng 302 thay vì 301/308: trình duyệt không nhớ chuyển hướng.",
      "Chuyển hướng về sai host (www ↔ không www) tạo chuỗi 2–3 bước; gộp thành một bước.",
    ],
    tradeoffs: ["Chuyển hướng HTTP→HTTPS chỉ bảo vệ khi khách bắt đầu bằng HTTPS ở lần sau (kết hợp HSTS). Lần đầu tiên vẫn đi qua HTTP một yêu cầu."],
    verify: ["curl -sI http://example.com/ | head -5   # kỳ vọng: 301 hoặc 308 + Location: https://…", "curl -sIL http://example.com/ | grep -i '^HTTP\\|^location'   # xem cả chuỗi chuyển hướng"],
    sources: [MDN("Web/HTTP/Guides/Redirections", "MDN: HTTP redirections"), R("Cloudflare: Always Use HTTPS", "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/"), OWASP_CS("Transport_Layer_Security_Cheat_Sheet", "OWASP Cheat Sheet: Transport Layer Security")],
  },

  "tls.protocol-version": {
    kind: "misconfiguration",
    mechanism: "TLS 1.0 và 1.1 đã chính thức bị khai tử (RFC 8996, 2021) vì dựa vào các thuật toán băm/CBC có điểm yếu thiết kế. Máy chủ vẫn chấp nhận chúng nghĩa là một client cũ (hoặc bị ép hạ cấp) có thể thương lượng bản yếu. Trình duyệt hiện đại dùng TLS 1.2/1.3 nên khách bình thường không bị ảnh hưởng.",
    frameworks: [
      S("cloudflare", "Cloudflare CDN", "text", "SSL/TLS → Edge Certificates → Minimum TLS Version = TLS 1.2 (hoặc cao hơn)."),
      S("nginx", "Nginx", "nginx", "ssl_protocols TLSv1.2 TLSv1.3;"),
      S("vercel", "Vercel", "text", "Vercel đã tắt TLS 1.0/1.1 ở biên; nếu quét vẫn thấy, kiểm tra có lớp proxy/CDN khác đứng trước không."),
    ],
    mistakes: ["Tắt TLS 1.2 vì “chỉ cần 1.3”: nhiều client doanh nghiệp/IoT vẫn cần 1.2.", "Chỉnh ssl_protocols ở một server block nhưng block mặc định (default_server) vẫn bật bản cũ."],
    tradeoffs: ["Client rất cũ (Android < 5, Windows XP, một số thiết bị thanh toán/IoT) sẽ không kết nối được sau khi tắt TLS 1.0/1.1. Kiểm tra nhật ký truy cập trước nếu khách của bạn có thiết bị cũ."],
    verify: ["openssl s_client -connect example.com:443 -tls1_2 </dev/null 2>&1 | grep -i 'protocol\\|cipher'   # phải kết nối được", "openssl s_client -connect example.com:443 -tls1_1 </dev/null 2>&1 | head -5   # phải bị từ chối (OpenSSL 3 có thể từ chối thử vì bản cũ; dùng nmap --script ssl-enum-ciphers -p 443 example.com thay thế)"],
    sources: [R("RFC 8996: Deprecating TLS 1.0 and 1.1", "https://www.rfc-editor.org/rfc/rfc8996"), R("Mozilla: Server Side TLS", "https://wiki.mozilla.org/Security/Server_Side_TLS"), OWASP_CS("Transport_Layer_Security_Cheat_Sheet", "OWASP Cheat Sheet: Transport Layer Security")],
  },

  "tls.certificate-expiry": {
    kind: "misconfiguration",
    mechanism: "Chứng chỉ có ngày hết hạn cố định. Khi hết hạn, trình duyệt chặn trang bằng cảnh báo toàn màn hình và các API gọi vào bị lỗi. Chứng chỉ công khai ngày càng ngắn (200 ngày từ 15/3/2026, 100 ngày từ 3/2027, 47 ngày từ 3/2029), nên việc gia hạn thủ công không bền; phải tự động.",
    frameworks: [
      S("vercel", "Vercel / Cloudflare / Supabase", "text", "Các nền tảng này tự cấp và gia hạn chứng chỉ cho tên miền đã gắn; nếu chứng chỉ sắp hết hạn, nguyên nhân thường là DNS bị đổi, bản ghi CAA chặn CA, hoặc tên miền không còn trỏ về nền tảng."),
      S("nginx", "Máy chủ tự quản (certbot)", "bash", L("sudo certbot renew --dry-run   # thử gia hạn không thay đổi gì", "systemctl list-timers | grep certbot   # phải có timer tự gia hạn")),
    ],
    mistakes: ["Tưởng tự gia hạn đang chạy nhưng thử thách HTTP-01 bị chặn bởi chuyển hướng/tường lửa/WAF.", "Gia hạn xong nhưng chưa tải lại (reload) máy chủ nên vẫn phục vụ chứng chỉ cũ.", "Bản ghi CAA chỉ cho phép CA khác với CA đang dùng."],
    tradeoffs: ["Chứng chỉ ngắn hạn an toàn hơn nhưng bắt buộc phải có tự động hoá và giám sát (cảnh báo khi còn ≤ 14 ngày)."],
    verify: ["echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -enddate", "dig +short CAA example.com   # CA đang dùng phải nằm trong danh sách"],
    sources: [R("Let's Encrypt: Integration Guide", "https://letsencrypt.org/docs/integration-guide/"), R("CA/Browser Forum: Baseline Requirements", "https://cabforum.org/baseline-requirements-documents/"), R("Cloudflare: Certificate lifetimes", "https://developers.cloudflare.com/ssl/")],
  },

  "cookies.flags": {
    kind: "misconfiguration",
    mechanism: "Ba thuộc tính chặn ba loại tấn công khác nhau. Secure: cookie không bao giờ đi qua http://. HttpOnly: JavaScript (kể cả script do kẻ tấn công chèn) không đọc được document.cookie. SameSite=Lax/Strict: trình duyệt không gửi cookie trong yêu cầu xuyên website (chủ yếu POST), giảm CSRF. Cookie phiên đăng nhập nên có đủ cả ba; cookie chỉ để giao diện đọc (theme, ngôn ngữ) có thể bỏ HttpOnly.",
    exchange: {
      before: "set-cookie: session=<giá-trị>; Path=/",
      after: "set-cookie: session=<giá-trị>; Path=/; Secure; HttpOnly; SameSite=Lax",
    },
    frameworks: [
      S("nextjs", "Next.js — Server Action / Route Handler", "ts", L(
        "import { cookies } from \"next/headers\";",
        "",
        "export async function POST() {",
        "  (await cookies()).set(\"session\", token, {",
        "    httpOnly: true, secure: true, sameSite: \"lax\", path: \"/\", maxAge: 60 * 60 * 24 * 7,",
        "  });",
        "  return new Response(null, { status: 204 });",
        "}",
      )),
      S("cloudflare", "Cloudflare Worker", "ts", "headers.append(\"Set-Cookie\", \"session=\" + token + \"; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800\");"),
      S("supabase", "Supabase (đăng nhập phía server)", "ts", L("// Dùng @supabase/ssr để phiên nằm trong cookie do server quản lý, không nằm trong localStorage.", "// Kiểm tra bộ tuỳ chọn cookie của bạn: secure: true, sameSite: \"lax\", path: \"/\" khi chạy production.")),
    ],
    mistakes: [
      "Đặt SameSite=None để “cho chạy mọi nơi” nhưng quên Secure: trình duyệt hiện đại từ chối lưu cookie.",
      "Thêm HttpOnly cho cookie mà JavaScript phía giao diện thật sự cần đọc (ví dụ token CSRF kiểu double-submit): tính năng hỏng. Tách thành hai cookie.",
      "Nghĩ SameSite thay thế hoàn toàn token CSRF: nó là lớp giảm thiểu, không phải bảo đảm tuyệt đối (ví dụ GET có tác dụng phụ, cùng site khác origin).",
      "Dùng tiền tố __Host- nhưng đặt Domain=… hoặc Path khác “/”: trình duyệt từ chối cookie.",
    ],
    tradeoffs: ["SameSite=Strict làm khách bấm liên kết từ email/website khác vào thấy như chưa đăng nhập ở lần tải đầu; Lax thường là điểm cân bằng.", "Cookie Secure không dùng được ở môi trường dev qua http://localhost trên một số trình duyệt cũ; localhost thường được ngoại lệ ở trình duyệt hiện đại."],
    verify: ["curl -sI https://example.com/ | grep -i set-cookie", "DevTools → Application → Cookies: cột Secure / HttpOnly / SameSite phải được đánh dấu cho cookie phiên"],
    sources: [MDN("Web/HTTP/Guides/Cookies", "MDN: Using HTTP cookies"), OWASP_CS("Session_Management_Cheat_Sheet", "OWASP Cheat Sheet: Session Management"), R("RFC 6265bis (cookie, bản nháp)", "https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html")],
  },

  "browser.cors": {
    kind: "misconfiguration",
    mechanism: "Chính sách cùng nguồn (same-origin policy) chặn trang của website A đọc phản hồi từ website B. CORS là cách B CHỦ ĐỘNG nới lỏng việc đó bằng Access-Control-Allow-Origin. Nếu B phản chiếu bất kỳ Origin nào và còn cho phép gửi cookie (Allow-Credentials: true), trang của kẻ tấn công có thể đọc dữ liệu tài khoản của khách đang đăng nhập vào B. `*` không kèm cookie thì chỉ lộ nội dung vốn công khai; trình duyệt tự chặn tổ hợp `*` + credentials.",
    exchange: {
      before: L("GET /api/me HTTP/1.1", "Origin: https://evil.example", "", "HTTP/1.1 200 OK", "access-control-allow-origin: https://evil.example", "access-control-allow-credentials: true"),
      after: L("GET /api/me HTTP/1.1", "Origin: https://evil.example", "", "HTTP/1.1 200 OK", "vary: Origin", "(không có access-control-allow-origin cho origin lạ)"),
    },
    frameworks: [
      S("cloudflare", "Cloudflare Worker — danh sách cho phép tường minh", "ts", L(
        "const ALLOWED = new Set([\"https://app.example.com\"]);",
        "",
        "function corsHeaders(request: Request): Headers {",
        "  const h = new Headers({ Vary: \"Origin\" });",
        "  const origin = request.headers.get(\"Origin\");",
        "  if (origin && ALLOWED.has(origin)) {",
        "    h.set(\"Access-Control-Allow-Origin\", origin);",
        "    h.set(\"Access-Control-Allow-Credentials\", \"true\");",
        "  }",
        "  return h;",
        "}",
      )),
      S("nextjs", "Next.js Route Handler", "ts", L(
        "const ALLOWED = new Set([\"https://app.example.com\"]);",
        "",
        "export async function GET(request: Request) {",
        "  const origin = request.headers.get(\"origin\") ?? \"\";",
        "  const headers = new Headers({ Vary: \"Origin\" });",
        "  if (ALLOWED.has(origin)) headers.set(\"Access-Control-Allow-Origin\", origin);",
        "  return Response.json({ ok: true }, { headers });",
        "}",
      )),
    ],
    mistakes: [
      "Phản chiếu header Origin vào Access-Control-Allow-Origin mà không so với danh sách (cách “cho chạy được” phổ biến nhất).",
      "Kiểm tra bằng `origin.endsWith(\"example.com\")`: evil-example.com cũng qua. So khớp nguyên văn cả chuỗi origin.",
      "Cho phép origin “null”: kẻ tấn công tạo được nó (iframe sandbox).",
      "Quên Vary: Origin: CDN cache phản hồi của origin này rồi trả cho origin khác.",
      "Nghĩ CORS bảo vệ API khỏi curl/máy chủ khác: CORS chỉ ràng buộc trình duyệt; API vẫn cần xác thực riêng.",
    ],
    tradeoffs: ["Danh sách cố định phải cập nhật khi thêm website client mới; đổi lại không có nguy cơ phản chiếu.", "API công khai (ảnh, dữ liệu mở) dùng `*` là hợp lệ nếu không có cookie/dữ liệu riêng."],
    verify: ["curl -sI -H 'Origin: https://khong-ton-tai.example' https://example.com/api/me | grep -i access-control", "Origin hợp lệ phải nhận lại đúng origin đó; origin lạ không được có Access-Control-Allow-Origin"],
    sources: [MDN("Web/HTTP/Guides/CORS", "MDN: CORS"), R("PortSwigger: CORS", "https://portswigger.net/web-security/cors"), R("Fetch Standard: CORS protocol", "https://fetch.spec.whatwg.org/#http-cors-protocol")],
  },

  "headers.frame-protection": {
    kind: "misconfiguration",
    mechanism: "Clickjacking: kẻ tấn công nhúng trang của bạn vào <iframe> trong suốt trên trang của họ, đặt nút của bạn dưới con trỏ chuột khách. frame-ancestors (CSP) hoặc X-Frame-Options báo cho trình duyệt rằng trang này không được nhúng (hoặc chỉ được nhúng bởi nguồn nhất định). frame-ancestors là chuẩn hiện hành; X-Frame-Options chỉ còn để tương thích trình duyệt cũ.",
    examples: [{ name: "content-security-policy", value: SIMPLE_CSP }, { name: "x-frame-options", value: "DENY" }],
    checks: ["headers.frame-protection"],
    frameworks: [...headerEverywhere("X-Frame-Options", "DENY"), S("generic", "Chỉ cho một nguồn nhúng (ví dụ cổng thanh toán)", "text", "Content-Security-Policy: frame-ancestors 'self' https://doi-tac.example")],
    mistakes: ["Dùng `X-Frame-Options: ALLOW-FROM …`: đã bị loại, trình duyệt bỏ qua cả dòng; dùng frame-ancestors.", "Đặt frame-ancestors trong thẻ <meta>: bị bỏ qua.", "Chặn nhúng toàn site làm hỏng widget/đối tác cần nhúng một trang công khai: đặt ngoại lệ theo đường dẫn."],
    tradeoffs: ["DENY chặn cả chính bạn nhúng trang vào nơi khác; dùng SAMEORIGIN hoặc frame-ancestors 'self' nếu cần."],
    verify: ["curl -sI https://example.com/ | grep -i 'x-frame-options\\|frame-ancestors'"],
    sources: [MDN("Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors", "MDN: frame-ancestors"), OWASP_CS("Clickjacking_Defense_Cheat_Sheet", "OWASP Cheat Sheet: Clickjacking Defense")],
  },

  "headers.x-content-type-options": {
    kind: "best-practice",
    mechanism: "Không có nosniff, trình duyệt có thể “đoán” loại tệp từ nội dung thay vì tin Content-Type, và chạy một tệp được tải lên như script hoặc stylesheet. nosniff bắt trình duyệt tin Content-Type, và chặn script/style có MIME sai. Rủi ro thực tế chủ yếu khi website cho người dùng tải tệp lên.",
    examples: [{ name: "x-content-type-options", value: XCTO }],
    checks: ["headers.x-content-type-options", "headers.broken"],
    frameworks: headerEverywhere("X-Content-Type-Options", XCTO),
    mistakes: ["Viết `nosniff;` hoặc `No-Sniff`: chỉ đúng nguyên văn “nosniff”.", "Bật nosniff rồi phát hiện tệp .js/.css bị phục vụ với Content-Type sai (text/plain): trang hỏng. Sửa Content-Type của tệp chứ không gỡ header."],
    tradeoffs: ["Hầu như không có đánh đổi; chỉ phơi bày các tệp đang phục vụ sai MIME."],
    verify: ["curl -sI https://example.com/ | grep -i x-content-type-options", "curl -sI https://example.com/_next/static/chunks/main.js | grep -i content-type"],
    sources: [MDN("Web/HTTP/Reference/Headers/X-Content-Type-Options", "MDN: X-Content-Type-Options"), R("Fetch Standard: nosniff", "https://fetch.spec.whatwg.org/#x-content-type-options-header")],
  },

  "privacy.referrer-policy": {
    kind: "best-practice",
    mechanism: "Referer là header trình duyệt gửi cho trang đích, cho biết khách đến từ URL nào. Khi không đặt chính sách, trình duyệt hiện đại tự dùng strict-origin-when-cross-origin (cùng origin: gửi URL đầy đủ; sang website khác: chỉ gửi tên miền; HTTPS→HTTP: không gửi). Đặt tường minh để không phụ thuộc mặc định của từng trình duyệt, và để không gửi URL đầy đủ nếu một trình duyệt cũ dùng mặc định cũ.",
    exchange: {
      before: L("(không đặt Referrer-Policy; trình duyệt cũ có thể gửi:)", "Referer: https://example.com/reset?token=abc123"),
      after: L("referrer-policy: " + REFERRER, "(sang website khác chỉ gửi:)", "Referer: https://example.com/"),
    },
    examples: [{ name: "referrer-policy", value: REFERRER }],
    checks: ["privacy.referrer-policy", "headers.broken"],
    frameworks: headerEverywhere("Referrer-Policy", REFERRER),
    mistakes: ["Đặt unsafe-url hoặc no-referrer-when-downgrade: gửi URL đầy đủ tới website khác.", "Để token/ID nhạy cảm trong URL rồi dựa vào Referrer-Policy: nên đưa token ra khỏi URL (dùng POST/header/cookie).", "Dùng no-referrer rồi hỏng tính năng dựa vào Referer (một số kiểm tra CSRF phía máy chủ, thống kê đối tác)."],
    tradeoffs: ["Chính sách chặt hơn (same-origin, no-referrer) bảo vệ tốt hơn nhưng làm công cụ analytics/đối tác mất dữ liệu nguồn truy cập."],
    verify: ["curl -sI https://example.com/ | grep -i referrer-policy"],
    sources: [MDN("Web/HTTP/Reference/Headers/Referrer-Policy", "MDN: Referrer-Policy"), R("W3C Referrer Policy", "https://www.w3.org/TR/referrer-policy/"), OWASP_CS("HTTP_Headers_Cheat_Sheet", "OWASP Cheat Sheet: HTTP Headers")],
  },

  "privacy.permissions-policy": {
    kind: "best-practice",
    mechanism: "Permissions-Policy cho phép tắt các tính năng mạnh của trình duyệt (camera, micro, vị trí…) cho trang của bạn và cho mọi iframe bên thứ ba trong đó. Nếu một script/iframe bên thứ ba bị xâm nhập, nó cũng không xin được các quyền bạn đã khoá.",
    examples: [{ name: "permissions-policy", value: PERMS }],
    checks: ["privacy.permissions-policy", "headers.broken"],
    frameworks: headerEverywhere("Permissions-Policy", PERMS),
    mistakes: ["Dùng cú pháp cũ Feature-Policy hoặc `camera 'none'`: sai cú pháp thì cả header bị bỏ qua. Cú pháp đúng: `camera=()`, `geolocation=(self)`.", "Khoá tính năng mà ứng dụng thật sự cần (payment cho Payment Request API, camera cho quét mã): chỉ khoá những gì bạn không dùng."],
    tradeoffs: ["Mỗi tính năng bạn không khoá là bề mặt cho iframe bên thứ ba; mỗi tính năng khoá nhầm là chức năng hỏng. Bắt đầu với camera, microphone, geolocation."],
    verify: ["curl -sI https://example.com/ | grep -i permissions-policy"],
    sources: [MDN("Web/HTTP/Reference/Headers/Permissions-Policy", "MDN: Permissions-Policy"), R("W3C Permissions Policy", "https://www.w3.org/TR/permissions-policy/")],
  },

  "config.server-disclosure": {
    kind: "best-practice",
    mechanism: "Server: nginx/1.18.0 hay X-Powered-By: Express cho bot biết chính xác phần mềm và phiên bản. Việc ẩn chúng KHÔNG vá được lỗ hổng (security through obscurity) nhưng làm bot quét hàng loạt khó nhắm đúng mục tiêu hơn. Điều quan trọng thật sự là cập nhật phần mềm.",
    frameworks: [
      S("nextjs", "Next.js", "ts", L("// next.config.ts", "const nextConfig = { poweredByHeader: false };", "export default nextConfig;")),
      S("nginx", "Nginx", "nginx", "server_tokens off;"),
      S("generic", "Express", "js", "app.disable(\"x-powered-by\");"),
      S("cloudflare", "Cloudflare", "text", "Cloudflare tự trả Server: cloudflare (không có số phiên bản) nên thường không cần xử lý."),
    ],
    mistakes: ["Coi việc ẩn header là đã “vá” phần mềm cũ.", "Xoá header ở ứng dụng nhưng proxy/CDN phía trước thêm lại."],
    tradeoffs: ["Gần như không có đánh đổi; chỉ làm khó chẩn đoán từ bên ngoài."],
    verify: ["curl -sI https://example.com/ | grep -i '^server:\\|x-powered-by'"],
    sources: [OWASP_CS("HTTP_Headers_Cheat_Sheet", "OWASP Cheat Sheet: HTTP Headers"), R("Next.js: poweredByHeader", "https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader")],
  },

  "exposure.secrets": {
    kind: "needs-evidence",
    mechanism: "Mã JavaScript gửi tới trình duyệt là công khai: bất kỳ khoá nào nằm trong đó, ai cũng đọc được. Trong Next.js, mọi biến môi trường có tiền tố NEXT_PUBLIC_ được NHÚNG vào mã phía khách lúc build. Quét thụ động chỉ khớp mẫu; một số khoá là công khai theo thiết kế (Stripe publishable key, Supabase anon key, khoá Firebase web). Khoá bí mật (Stripe sk_live, Supabase service_role, khoá cơ sở dữ liệu, AWS secret) mà lộ phải coi là đã bị lộ vĩnh viễn.",
    exchange: {
      before: L("GET /_next/static/chunks/app.js", "", "…const supabase=createClient(url,\"eyJ…service_role…\")…"),
      after: L("GET /_next/static/chunks/app.js", "", "…fetch(\"/api/orders\")…   // khoá bí mật chỉ nằm ở máy chủ"),
    },
    frameworks: [
      S("nextjs", "Next.js: chỉ máy chủ mới đọc được khoá bí mật", "ts", L("// KHÔNG đặt NEXT_PUBLIC_ cho khoá bí mật", "// app/api/orders/route.ts (chạy trên máy chủ)", "const key = process.env.STRIPE_SECRET_KEY; // không có tiền tố NEXT_PUBLIC_")),
      S("cloudflare", "Cloudflare Workers: lưu bí mật bằng secret, không đặt trong mã", "bash", L("npx wrangler secret put STRIPE_SECRET_KEY", "# trong Worker: env.STRIPE_SECRET_KEY")),
      S("vercel", "Vercel", "text", "Project → Settings → Environment Variables: đặt biến bí mật (không có tiền tố NEXT_PUBLIC_), đánh dấu Sensitive nếu có tuỳ chọn."),
      S("supabase", "Supabase", "text", "Trong trình duyệt chỉ dùng anon/publishable key. service_role (hoặc secret key) chỉ dùng ở máy chủ; nó bỏ qua toàn bộ RLS. Nếu service_role đã lộ: tạo lại (rotate) khoá trong Project Settings → API."),
    ],
    mistakes: [
      "Xoá khoá khỏi mã rồi cho rằng xong: khoá vẫn nằm trong lịch sử git, bản build cũ, cache CDN. Phải XOAY (đổi) khoá ở nhà cung cấp.",
      "Đặt khoá bí mật vào biến NEXT_PUBLIC_… “cho tiện gọi từ component”.",
      "Hoảng với mọi khớp mẫu: khoá công khai theo thiết kế (Stripe pk_, Supabase anon) không phải lỗi; việc bảo vệ nằm ở quyền truy cập phía sau.",
      "Che khoá trong repo bằng .gitignore nhưng vẫn commit tệp .env từ trước.",
    ],
    tradeoffs: ["Chuyển lời gọi dùng khoá bí mật sang route phía máy chủ thêm một bước trung gian nhưng là cách duy nhất giữ khoá kín.", "Xoay khoá làm hỏng mọi dịch vụ đang dùng khoá cũ cho tới khi cập nhật; lên kế hoạch thay đồng thời."],
    verify: ["curl -s https://example.com/_next/static/chunks/<tệp>.js | grep -c 'sk_live\\|service_role'   # kỳ vọng 0", "git log -p -S'<tiền-tố-khoá>' --all   # kiểm tra lịch sử repo (chỉ chạy ở máy bạn)", "Kiểm tra bảng điều khiển nhà cung cấp: khoá cũ đã bị vô hiệu hoá"],
    sources: [OWASP_CS("Secrets_Management_Cheat_Sheet", "OWASP Cheat Sheet: Secrets Management"), R("Next.js: Environment Variables", "https://nextjs.org/docs/app/guides/environment-variables"), R("Supabase: API keys", "https://supabase.com/docs/guides/api/api-keys"), R("Cloudflare Workers: Secrets", "https://developers.cloudflare.com/workers/configuration/secrets/")],
  },

  "exposure.public-config": {
    kind: "best-practice",
    mechanism: "Cấu hình công khai (URL Supabase, khoá anon, cấu hình Firebase) được thiết kế để nằm trong trình duyệt. Chúng không phải bí mật; bảo mật nằm ở quy tắc truy cập phía dịch vụ: Row Level Security (RLS) của Supabase hoặc Security Rules của Firebase. Nếu RLS tắt trên bảng ở schema public, ai có khoá anon (tức mọi khách) đọc/ghi được bảng đó qua API.",
    frameworks: [
      S("supabase", "Supabase: bật RLS và chỉ cho người dùng thấy dòng của mình", "sql", L(
        "alter table public.notes enable row level security;",
        "",
        "create policy \"Chỉ chủ sở hữu được đọc\"",
        "  on public.notes for select to authenticated",
        "  using ((select auth.uid()) = user_id);",
        "",
        "create policy \"Chỉ chủ sở hữu được ghi\"",
        "  on public.notes for insert to authenticated",
        "  with check ((select auth.uid()) = user_id);",
      )),
      S("supabase", "Supabase: tìm bảng chưa bật RLS (chạy trong SQL editor, chỉ đọc)", "sql", "select schemaname, tablename from pg_tables where schemaname = 'public' and rowsecurity = false;"),
    ],
    mistakes: ["Bật RLS nhưng không tạo policy: bảng bị khoá hoàn toàn, rồi “sửa nhanh” bằng policy `using (true)` — mở cho tất cả.", "Dùng service_role ở client cho tiện (bỏ qua RLS).", "Chỉ kiểm tra RLS cho SELECT, quên INSERT/UPDATE/DELETE.", "View hoặc function SECURITY DEFINER bỏ qua RLS của bảng gốc."],
    tradeoffs: ["RLS thêm chi phí truy vấn; đặt cột dùng trong policy (ví dụ user_id) có index.", "Policy phức tạp khó kiểm thử; viết test với vai trò anon và authenticated trước khi triển khai."],
    verify: ["Chạy truy vấn pg_tables ở trên: không còn bảng nhạy cảm nào có rowsecurity = false", "Từ ngoài: curl -s 'https://<ref>.supabase.co/rest/v1/<bảng>?select=*&limit=1' -H 'apikey: <anon-key>'   # kỳ vọng [] hoặc lỗi quyền, không trả dữ liệu riêng (chỉ thử trên dự án của bạn)"],
    sources: [R("Supabase: Row Level Security", "https://supabase.com/docs/guides/database/postgres/row-level-security"), R("Firebase: Security Rules", "https://firebase.google.com/docs/rules"), OWASP_CS("Secrets_Management_Cheat_Sheet", "OWASP Cheat Sheet: Secrets Management")],
  },

  "exposure.source-maps": {
    kind: "best-practice",
    mechanism: "Source map (.map) cho phép dựng lại mã nguồn gốc (chưa nén) từ bundle. Lộ source map không tự là lỗ hổng, nhưng giúp kẻ tấn công đọc logic, tìm endpoint ẩn và comment nội bộ nhanh hơn. Mã phía khách vốn đã công khai; source map chỉ làm nó dễ đọc hơn.",
    frameworks: [
      S("nextjs", "Next.js: mặc định KHÔNG phát hành source map trình duyệt ở production", "ts", L("// next.config.ts — đảm bảo không bật", "const nextConfig = { productionBrowserSourceMaps: false };", "export default nextConfig;")),
      S("generic", "Dùng công cụ báo lỗi (Sentry…): tải map lên rồi xoá khỏi thư mục phát hành", "bash", L("# sau bước upload source map lên dịch vụ báo lỗi:", "find .next out dist -name '*.map' -delete")),
    ],
    mistakes: ["Chỉ xoá chú thích //# sourceMappingURL nhưng để tệp .map trên máy chủ: ai biết đường dẫn vẫn tải được.", "Chặn .map bằng robots.txt: robots.txt không phải kiểm soát truy cập."],
    tradeoffs: ["Không có source map ở production thì stack trace lỗi khó đọc; giải pháp là upload map riêng cho dịch vụ báo lỗi, không phục vụ công khai."],
    verify: ["curl -sI https://example.com/_next/static/chunks/<tệp>.js.map | head -1   # kỳ vọng 404"],
    sources: [R("Next.js: productionBrowserSourceMaps", "https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps"), MDN("Tools/Debugger/How_to/Use_a_source_map", "MDN: Use a source map"), R("CWE-540: Inclusion of Sensitive Information in Source Code", "https://cwe.mitre.org/data/definitions/540.html")],
  },

  "exposure.error-page-disclosure": {
    kind: "misconfiguration",
    mechanism: "Trang lỗi ở chế độ debug in stack trace, đường dẫn tệp, phiên bản framework, đôi khi cả biến môi trường hoặc truy vấn SQL. Kẻ tấn công cố tình gây lỗi (tham số sai, đường dẫn lạ) để đọc những thông tin này. Production chỉ nên trả thông điệp chung; chi tiết ghi vào nhật ký phía máy chủ.",
    frameworks: [
      S("nextjs", "Next.js: giữ NODE_ENV=production và dùng trang lỗi riêng", "ts", L("// app/error.tsx (Client Component)", "\"use client\";", "export default function Error() {", "  return <p>Có lỗi xảy ra. Vui lòng thử lại sau.</p>; // không in error.message", "}")),
      S("generic", "Các framework khác", "text", "Django: DEBUG = False · Laravel: APP_DEBUG=false · Rails: config.consider_all_requests_local = false · Express: NODE_ENV=production"),
    ],
    mistakes: ["Tắt debug nhưng trang 500 của máy chủ web/CDN vẫn in chi tiết.", "In error.message của lỗi cơ sở dữ liệu ra JSON của API."],
    tradeoffs: ["Thông điệp chung làm chẩn đoán khó hơn; bù lại bằng mã tham chiếu lỗi (error id) hiển thị cho khách và ghi cùng stack trace trong nhật ký."],
    verify: ["curl -s https://example.com/duong-dan-khong-ton-tai-123 | head -20   # chỉ thông điệp chung, không đường dẫn tệp/stack trace"],
    sources: [OWASP_CS("Error_Handling_Cheat_Sheet", "OWASP Cheat Sheet: Error Handling"), R("OWASP WSTG: Improper Error Handling", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling")],
  },

  "browser.third-party-integrity": {
    kind: "best-practice",
    mechanism: "Subresource Integrity (SRI): thuộc tính integrity chứa mã băm của tệp mong đợi. Nếu CDN bị xâm nhập và trả tệp khác, trình duyệt từ chối chạy. Chỉ có ý nghĩa khi bạn ghim phiên bản cụ thể; tệp “latest” thay đổi sẽ làm mã băm sai.",
    exchange: {
      before: "<script src=\"https://cdn.example.net/lib@3.4.1/lib.min.js\"></script>",
      after: "<script src=\"https://cdn.example.net/lib@3.4.1/lib.min.js\" integrity=\"sha384-<mã-băm>\" crossorigin=\"anonymous\"></script>",
    },
    frameworks: [
      S("generic", "Tính mã băm SRI", "bash", "curl -s https://cdn.example.net/lib@3.4.1/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A"),
      S("nextjs", "Next.js", "text", "Cách an toàn nhất: tự phục vụ thư viện từ cùng origin (npm install + bundle) thay vì nạp từ CDN bên thứ ba; khi không thể, thêm integrity và crossOrigin vào thẻ script."),
    ],
    mistakes: ["Thêm integrity cho URL không ghim phiên bản (…@latest): khi CDN cập nhật, trang hỏng.", "Quên crossorigin=\"anonymous\": trình duyệt có thể không kiểm tra hoặc từ chối tải tài nguyên khác origin.", "Thêm SRI cho script bên thứ ba vốn thay đổi liên tục (analytics, chat): không áp dụng được; dùng CSP và đánh giá nhà cung cấp."],
    tradeoffs: ["Mỗi lần nâng cấp thư viện phải tính lại mã băm; đổi lại chặn được tấn công chuỗi cung ứng qua CDN."],
    verify: ["curl -s https://example.com/ | grep -o '<script[^>]*src=\"https://[^>]*>' | grep -vc integrity   # kỳ vọng 0 cho script CDN"],
    sources: [MDN("Web/Security/Subresource_Integrity", "MDN: Subresource Integrity"), R("W3C Subresource Integrity", "https://www.w3.org/TR/SRI/")],
  },

  "adv.web-storage-secrets": {
    kind: "needs-evidence",
    mechanism: "localStorage/sessionStorage đọc được bởi mọi JavaScript chạy trên trang. Nếu có XSS (hoặc một script bên thứ ba bị xâm nhập), kẻ tấn công lấy được token ở đó. Cookie HttpOnly thì JavaScript không đọc được. Quét tĩnh chỉ thấy lời gọi ghi vào storage với tên giống token; chưa chắc giá trị là token thật.",
    frameworks: [
      S("nextjs", "Next.js: lưu phiên trong cookie HttpOnly do máy chủ cấp", "ts", L("(await cookies()).set(\"session\", token, { httpOnly: true, secure: true, sameSite: \"lax\", path: \"/\" });")),
      S("supabase", "Supabase", "text", "supabase-js phía trình duyệt lưu phiên trong localStorage theo mặc định. Với ứng dụng cần mức bảo vệ cao hơn, dùng @supabase/ssr để quản lý phiên bằng cookie phía máy chủ, và siết CSP để giảm nguy cơ XSS."),
    ],
    mistakes: ["Chuyển token sang cookie nhưng quên HttpOnly nên không cải thiện gì.", "Lưu cả refresh token dài hạn trong localStorage."],
    tradeoffs: ["Cookie phiên cần chống CSRF (SameSite + token); localStorage thì miễn nhiễm CSRF nhưng lộ khi có XSS. Không có lựa chọn miễn phí; chọn theo mô hình đe doạ."],
    verify: ["Kiểm tra mã nguồn: grep -rn \"localStorage.setItem\" src/ và xem giá trị có phải token", "DevTools → Application → Local Storage: có khoá giống token/JWT không"],
    sources: [OWASP_CS("HTML5_Security_Cheat_Sheet", "OWASP Cheat Sheet: HTML5 Security"), OWASP_CS("Session_Management_Cheat_Sheet", "OWASP Cheat Sheet: Session Management")],
  },

  "adv.dom-xss-flow": {
    kind: "needs-evidence",
    mechanism: "DOM XSS xảy ra khi dữ liệu người dùng kiểm soát (location.hash, location.search, postMessage) chảy vào một “sink” nguy hiểm (innerHTML, document.write, eval). Công cụ quét thụ động chỉ tìm mẫu mã có dạng source→sink; nó KHÔNG chứng minh dữ liệu thật sự tới được sink mà không bị lọc. Độ tin cậy thấp: cần người đọc mã xác minh.",
    frameworks: [
      S("generic", "Thay sink nguy hiểm bằng sink an toàn", "js", L("// Không an toàn", "el.innerHTML = location.hash.slice(1);", "", "// An toàn: coi dữ liệu là văn bản", "el.textContent = location.hash.slice(1);")),
      S("nextjs", "React/Next.js", "tsx", L("// React tự escape khi render {value}. Tránh dangerouslySetInnerHTML với dữ liệu người dùng.", "// Nếu bắt buộc, làm sạch bằng thư viện chuyên dụng (DOMPurify) ở phía khách.")),
    ],
    mistakes: ["Tự viết regex lọc <script>: dễ bị vượt qua; dùng textContent hoặc thư viện làm sạch.", "Coi phát hiện này là chắc chắn có lỗ hổng, hoặc bỏ qua vì “chỉ là dấu hiệu”. Cả hai đều sai: hãy đọc đúng đoạn mã được chỉ ra."],
    tradeoffs: ["Trusted Types (CSP: require-trusted-types-for 'script') chặn cả lớp lỗi này nhưng cần sửa mã; hỗ trợ trình duyệt chưa đồng đều."],
    verify: ["Đọc đúng đoạn mã được chỉ ra và xác định dữ liệu vào sink có thể do người dùng kiểm soát không", "Thử bằng chuỗi vô hại trên môi trường của bạn, ví dụ #<b>test</b>, và xem trang có diễn giải HTML hay không"],
    sources: [OWASP_CS("DOM_based_XSS_Prevention_Cheat_Sheet", "OWASP Cheat Sheet: DOM based XSS Prevention"), MDN("Web/API/Trusted_Types_API", "MDN: Trusted Types API")],
  },

  "headers.cache-policy": {
    kind: "best-practice",
    mechanism: "Cache-Control quyết định ai được lưu bản sao phản hồi và dùng lại. `no-store` = không lưu ở đâu cả. `no-cache` = được lưu nhưng phải hỏi lại máy chủ trước khi dùng (KHÔNG có nghĩa là không lưu). `private` = chỉ trình duyệt của khách được lưu, cache dùng chung (CDN/proxy) thì không. Trang có dữ liệu cá nhân cần private hoặc no-store.",
    exchange: {
      before: L("GET /account HTTP/2", "Cookie: session=…", "", "HTTP/2 200", "cache-control: public, max-age=3600"),
      after: L("GET /account HTTP/2", "Cookie: session=…", "", "HTTP/2 200", "cache-control: private, no-store"),
    },
    frameworks: [
      S("nextjs", "Next.js Route Handler / trang động", "ts", "return new Response(body, { headers: { \"Cache-Control\": \"private, no-store\" } });"),
      S("cloudflare", "Cloudflare", "text", "Rules → Cache Rules: KHÔNG đặt “Cache everything” cho đường dẫn có đăng nhập; nếu bắt buộc, thêm điều kiện bỏ qua cache khi có cookie phiên."),
    ],
    mistakes: ["Dùng no-cache với ý định “không lưu”.", "Đặt Cache-Control: public trên phản hồi có Set-Cookie hoặc dữ liệu theo người dùng.", "Quy tắc “Cache everything” của CDN ghi đè Cache-Control của ứng dụng."],
    tradeoffs: ["no-store tắt cả cache hữu ích của trình duyệt (nút Back chậm hơn, tốn băng thông); chỉ dùng cho trang thật sự nhạy cảm."],
    verify: ["curl -sI -H 'Cookie: <phiên-của-bạn>' https://example.com/account | grep -i cache-control", "Gọi hai lần và xem header age/cf-cache-status: trang cá nhân không được là HIT"],
    sources: [MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching"), R("RFC 9111: HTTP Caching", "https://www.rfc-editor.org/rfc/rfc9111"), OWASP_CS("HTTP_Headers_Cheat_Sheet", "OWASP Cheat Sheet: HTTP Headers")],
  },

  "adv.shared-cache-leak": {
    kind: "misconfiguration",
    mechanism: "Khi CDN/proxy dùng chung lưu một phản hồi theo người dùng (có cookie hoặc dữ liệu cá nhân) rồi phục vụ lại cho người khác, người sau thấy dữ liệu của người trước. Dấu hiệu quan sát được: phản hồi có Set-Cookie/dữ liệu riêng nhưng Cache-Control public hoặc có header chứng tỏ HIT từ cache dùng chung.",
    frameworks: [
      S("nextjs", "Next.js", "ts", "return new Response(body, { headers: { \"Cache-Control\": \"private, no-store\", Vary: \"Cookie\" } });"),
      S("cloudflare", "Cloudflare", "text", "Kiểm tra Cache Rules và Page Rules: loại trừ đường dẫn có đăng nhập khỏi “Cache everything”; xoá cache (Purge) sau khi sửa."),
    ],
    mistakes: ["Sửa Cache-Control nhưng quên xoá (purge) bản đã lưu: vẫn còn phục vụ dữ liệu cũ.", "Dùng Vary: Cookie như giải pháp duy nhất: tỉ lệ cache thấp và dễ sai; ưu tiên private/no-store."],
    tradeoffs: ["Loại trừ trang cá nhân khỏi cache giảm hiệu năng CDN cho các trang đó; bù bằng cache dữ liệu công khai riêng."],
    verify: ["curl -sI https://example.com/account | grep -i 'cache-control\\|age\\|cf-cache-status\\|x-cache'", "Sau khi sửa, purge cache CDN rồi kiểm tra lại"],
    sources: [R("RFC 9111: HTTP Caching", "https://www.rfc-editor.org/rfc/rfc9111"), R("PortSwigger: Web cache deception", "https://portswigger.net/web-security/web-cache-deception"), MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching")],
  },

  "config.dns-email-security": {
    kind: "best-practice",
    mechanism: "SPF liệt kê máy chủ được phép gửi thư cho tên miền; DKIM ký thư; DMARC báo nhà cung cấp thư phải làm gì khi SPF/DKIM không khớp với miền ở From:. Không có DMARC ở chế độ quarantine/reject, thư giả danh tên miền của bạn dễ vào hộp thư người nhận. Quét từ ngoài không biết tên miền có thực sự gửi thư, nên khuyến nghị phụ thuộc ngữ cảnh.",
    frameworks: [
      S("generic", "Bản ghi DNS khi tên miền CÓ gửi thư (bắt đầu theo dõi)", "text", L("example.com.        TXT  \"v=spf1 include:_spf.nha-cung-cap-mail.example ~all\"", "_dmarc.example.com. TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"", "# Sau vài tuần đọc báo cáo: p=quarantine, rồi p=reject")),
      S("generic", "Bản ghi DNS khi tên miền KHÔNG gửi/nhận thư", "text", L("example.com.        TXT  \"v=spf1 -all\"", "_dmarc.example.com. TXT  \"v=DMARC1; p=reject;\"", "example.com.        MX   0 .   # Null MX (RFC 7505): không nhận thư")),
      S("cloudflare", "Cloudflare DNS", "text", "DNS → Records → Add record → Type TXT, Name theo bảng trên. Đặt “Proxy status” không áp dụng cho TXT."),
    ],
    mistakes: ["Có hai bản ghi SPF cho cùng tên miền: SPF lỗi (permerror); gộp thành một.", "SPF vượt 10 lần tra DNS (include lồng nhau): SPF lỗi; rút gọn bớt include.", "Bật p=reject ngay mà chưa theo dõi: thư hợp lệ từ dịch vụ bên thứ ba (newsletter, CRM) bị loại.", "Dùng +all hoặc ?all: cho phép/không kiểm soát bất kỳ ai gửi."],
    tradeoffs: ["p=reject bảo vệ nhất nhưng đòi hỏi mọi nguồn gửi hợp lệ đều đã được cấu hình SPF/DKIM; nâng dần none → quarantine → reject."],
    verify: ["dig +short TXT example.com | grep spf1", "dig +short TXT _dmarc.example.com", "dig +short MX example.com"],
    sources: [R("RFC 7208: SPF", "https://www.rfc-editor.org/rfc/rfc7208"), R("RFC 7489: DMARC", "https://www.rfc-editor.org/rfc/rfc7489"), R("RFC 7505: Null MX", "https://www.rfc-editor.org/rfc/rfc7505"), R("Cloudflare: DMARC, SPF, DKIM", "https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/")],
  },

  "exposure.subdomain-takeover": {
    kind: "needs-evidence",
    mechanism: "Tên miền con (blog.example.com) có CNAME trỏ tới dịch vụ ngoài (GitHub Pages, Heroku, bucket…) mà tài nguyên ở đó đã bị xoá. Kẻ khác đăng ký đúng tài nguyên đó có thể phục vụ nội dung dưới tên miền của bạn (lừa đảo, đánh cắp cookie phạm vi tên miền cha). Quét chỉ thấy CNAME trỏ tới dịch vụ có “dấu hiệu trống”; chưa thử đăng ký nên chưa khẳng định chiếm được.",
    frameworks: [
      S("cloudflare", "Cloudflare DNS", "text", "DNS → Records: xoá bản ghi CNAME không còn dùng, hoặc trỏ lại về tài nguyên bạn kiểm soát."),
      S("generic", "Kiểm kê tên miền con", "bash", L("dig +short CNAME blog.example.com", "curl -sI https://blog.example.com/ | head -3   # trang “There isn’t a GitHub Pages site here” là dấu hiệu")),
    ],
    mistakes: ["Xoá dịch vụ ngoài trước rồi quên xoá bản ghi DNS (thứ tự đúng: xoá DNS trước).", "Chỉ kiểm tra tên miền chính, bỏ sót tên miền con cũ."],
    tradeoffs: ["Kiểm kê DNS định kỳ tốn công nhưng là cách duy nhất ngăn lớp lỗi này; tự động hoá bằng rà soát CNAME hàng tháng."],
    verify: ["dig +short CNAME <tên-miền-con>", "Mở tên miền con trong trình duyệt: không được hiện trang “chưa có site/ chưa cấu hình” của nhà cung cấp"],
    sources: [R("OWASP WSTG: Subdomain Takeover", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"), R("GitHub: dangling DNS", "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages")],
  },

  "config.http-methods": {
    kind: "needs-evidence",
    mechanism: "Phản hồi OPTIONS (header Allow) liệt kê phương thức máy chủ khai báo; không có nghĩa phương thức đó thật sự xử lý được. TRACE bật nghĩa là máy chủ phản hồi lại yêu cầu (đã từng bị dùng để đọc header nhạy cảm); PUT/DELETE chỉ nguy hiểm nếu đường dẫn đó cho ghi/xoá mà không cần xác thực. Quét không gửi yêu cầu ghi nên chưa thể kết luận.",
    frameworks: [
      S("nginx", "Nginx", "nginx", L("# Chỉ cho phép GET, HEAD, POST", "if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }")),
      S("nextjs", "Next.js Route Handler", "ts", "// Chỉ export các phương thức bạn hỗ trợ; Next trả 405 cho phần còn lại.\nexport async function GET() { /* … */ }"),
    ],
    mistakes: ["Chặn phương thức ở một đường dẫn nhưng không ở API khác.", "Dựa vào việc ẩn phương thức thay vì bắt buộc xác thực và phân quyền cho mọi thao tác ghi."],
    tradeoffs: ["Chặn phương thức không dùng gần như không tốn gì; nhưng đừng chặn OPTIONS nếu API cần CORS preflight."],
    verify: ["curl -si -X OPTIONS https://example.com/ | grep -i '^allow'", "curl -si -X TRACE https://example.com/ | head -1   # kỳ vọng 405 hoặc 501"],
    sources: [MDN("Web/HTTP/Reference/Methods", "MDN: HTTP request methods"), OWASP_CS("REST_Security_Cheat_Sheet", "OWASP Cheat Sheet: REST Security")],
  },
};

/** Danh sách luật có tầng đào sâu (dùng cho kiểm tra và tài liệu). */
export const DEEP_DIVE_RULES = Object.keys(DEEP_DIVE);
