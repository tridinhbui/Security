import { headerSnippets, RECOMMENDED } from "./remediation";
import type { Finding, Platform, Remediation, Snippet } from "./types";

/**
 * Thư viện lệnh khắc phục: mọi phát hiện đang lỗi đều được gắn lệnh/cấu hình có thể DÁN thẳng, cộng một lệnh để kiểm tra lại.
 * Quy ước an toàn:
 *  - Chỉ chèn `host` (đã qua kiểm tra hostname) vào lệnh; mọi giá trị khác là chỗ giữ chỗ rõ ràng (EXAMPLE…).
 *  - Không có lệnh phá huỷ: không rm, không sed -i, không ghi đè file. Chỉ grep/curl/openssl/dig để kiểm tra, hoặc cấu hình để bạn tự thêm.
 *  - Khi chưa nhận diện được nền tảng, đưa ra MỌI lựa chọn có nhãn rõ ràng để bạn chọn đúng cái mình dùng (không đoán thay bạn).
 */
export interface FixCtx { host: string; platforms: Platform[]; finding: Finding; now: Date }
type FixFn = (c: FixCtx) => Snippet[];

const S = (label: string, language: string, code: string, platform: Snippet["platform"] = "generic"): Snippet => ({ platform, label, language, code });
const has = (c: FixCtx, p: Platform) => c.platforms.includes(p);
const HOST_OK = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;

const hdr = (name: string, value: string, c: FixCtx) => headerSnippets(name, value, c.platforms);
const curlHeader = (host: string, names: string) => `curl -sI https://${host}/ | grep -iE "^(${names}):"`;

// ------------------------------------------------------------------ lệnh theo từng luật

const certbot = (host: string, extra = ""): Snippet[] => [
  S("Let's Encrypt trên máy chủ Linux — Nginx", "bash", `sudo apt update && sudo apt install -y certbot python3-certbot-nginx\nsudo certbot --nginx -d ${host}${extra}`),
  S("Let's Encrypt trên máy chủ Linux — Apache", "bash", `sudo apt update && sudo apt install -y certbot python3-certbot-apache\nsudo certbot --apache -d ${host}${extra}`),
  S("Cloudflare (website đi qua proxy)", "text", "SSL/TLS → Overview → chọn “Full (strict)”.\nSSL/TLS → Edge Certificates → bật “Always Use HTTPS”."),
  S("Hosting/nền tảng quản lý sẵn (Vercel, Netlify, Cloudflare Pages…)", "text", "Thêm tên miền vào dự án trong bảng điều khiển; chứng chỉ HTTPS được cấp và gia hạn tự động."),
];

const opensslCert = (host: string) => `echo | openssl s_client -servername ${host} -connect ${host}:443 2>/dev/null | openssl x509 -noout -dates -issuer -subject`;

export const FIXES: Record<string, FixFn> = {
  // ---- TLS / truyền tải
  "tls.https-available": (c) => [...certbot(c.host), S("Kiểm tra", "bash", `curl -vI https://${c.host}/ 2>&1 | grep -iE "SSL certificate|subject|expire|HTTP/"`)],
  "tls.certificate-expiry": (c) => [
    S("Gia hạn chứng chỉ Let's Encrypt ngay", "bash", "sudo certbot renew --dry-run   # thử trước, không thay đổi gì\nsudo certbot renew             # gia hạn thật\nsudo systemctl reload nginx    # hoặc apache2 / caddy tuỳ máy chủ của bạn"),
    S("Bảo đảm tự gia hạn đang chạy", "bash", "systemctl list-timers | grep -i certbot   # phải thấy một lịch chạy định kỳ"),
    S("Kiểm tra ngày hết hạn", "bash", opensslCert(c.host)),
  ],
  "tls.certificate-strength": (c) => [
    S("Cấp lại chứng chỉ ECDSA (mạnh, nhanh) bằng Let's Encrypt", "bash", `sudo certbot certonly --nginx --key-type ecdsa --elliptic-curve secp256r1 -d ${c.host}   # đổi --nginx thành --apache nếu cần`),
    S("Kiểm tra loại khoá và thuật toán chữ ký", "bash", `echo | openssl s_client -servername ${c.host} -connect ${c.host}:443 2>/dev/null | openssl x509 -noout -text | grep -E "Public-Key|Signature Algorithm|Not After"`),
  ],
  "tls.protocol-version": (c) => [
    S("Nginx", "nginx", "ssl_protocols TLSv1.2 TLSv1.3;\n# sau đó: sudo nginx -t && sudo systemctl reload nginx", "nginx"),
    S("Apache", "apache", "SSLProtocol -all +TLSv1.2 +TLSv1.3\n# sau đó: sudo apachectl configtest && sudo systemctl reload apache2", "apache"),
    S("Cloudflare", "text", "SSL/TLS → Edge Certificates → Minimum TLS Version → chọn “TLS 1.2”.", "cloudflare"),
    S("Kiểm tra: kết nối TLS 1.1 phải THẤT BẠI", "bash", `openssl s_client -connect ${c.host}:443 -servername ${c.host} -tls1_1 </dev/null 2>&1 | grep -iE "alert|handshake failure|no protocols|Protocol *:"`),
  ],
  "tls.http2": (c) => [
    S("Nginx (1.25.1+)", "nginx", "listen 443 ssl;\nhttp2 on;", "nginx"),
    S("Nginx (cũ hơn 1.25.1)", "nginx", "listen 443 ssl http2;", "nginx"),
    S("Apache", "apache", "# bật module rồi thêm vào vhost HTTPS\n#   sudo a2enmod http2\nProtocols h2 http/1.1", "apache"),
    S("Cloudflare", "text", "Network → HTTP/2 → On.", "cloudflare"),
    S("Kiểm tra", "bash", `curl -sI --http2 https://${c.host}/ | head -1   # mong đợi: HTTP/2 200`),
  ],
  "tls.http-to-https-redirect": (c) => [S("Kiểm tra: phải thấy 301/308 và Location bắt đầu bằng https://", "bash", `curl -sI http://${c.host}/ | grep -iE "^(HTTP|location)"`)],
  "tls.www-consistency": (c) => {
    const apex = c.host.replace(/^www\./, "");
    return [
      S("Nginx — chuyển hướng www về tên miền chính (một nơi duy nhất)", "nginx", `server {\n  listen 443 ssl;\n  server_name www.${apex};\n  # (giữ nguyên các dòng ssl_certificate của bạn)\n  return 301 https://${apex}$request_uri;\n}`, "nginx"),
      S("Cloudflare", "text", `Rules → Redirect Rules → Create rule\nKhi hostname bằng www.${apex} → Dynamic redirect tới concat("https://${apex}", http.request.uri.path), mã 301.`, "cloudflare"),
      S("Kiểm tra cả hai địa chỉ", "bash", `for h in ${apex} www.${apex}; do echo "== $h"; curl -sI https://$h/ | grep -iE "^(HTTP|location)"; done`),
    ];
  },
  "tls.hsts": (c) => [...hdr("Strict-Transport-Security", RECOMMENDED.hsts, c), S("Kiểm tra", "bash", curlHeader(c.host, "strict-transport-security"))],
  "tls.insecure-login-form": (c) => [
    S("Sửa form: dùng POST và địa chỉ HTTPS (hoặc đường dẫn tương đối)", "html", `<form method="post" action="https://${c.host}/login">\n  <!-- ... -->\n</form>`),
    S("Tìm mọi form còn trỏ tới http:// trong mã nguồn của bạn", "bash", `grep -rnE "action=[\\"']http://" --include="*.html" --include="*.js" --include="*.jsx" --include="*.tsx" --include="*.php" . 2>/dev/null | head -30`),
  ],

  "tls.hsts-preload": (c) => [
    ...hdr("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload", c),
    S("Chỉ thêm preload khi MỌI tên miền con đều chạy HTTPS. Sau khi triển khai header, đăng ký tại https://hstspreload.org/", "bash", `curl -s "https://hstspreload.org/api/v2/status?domain=${c.host.replace(/^www\./, "")}"   # xem tình trạng preload hiện tại`),
    S("Kiểm tra", "bash", curlHeader(c.host, "strict-transport-security")),
  ],
  "tls.cipher-suite": (c) => [
    S("Nginx — bộ mã hoá “Intermediate” của Mozilla", "nginx", "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;", "nginx"),
    S("Apache", "apache", "SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305\nSSLHonorCipherOrder off", "apache"),
    S("Cloudflare", "text", "SSL/TLS → Edge Certificates → bật TLS 1.3; Minimum TLS Version = 1.2.", "cloudflare"),
    S("Kiểm tra giao thức và bộ mã hoá thương lượng", "bash", `openssl s_client -connect ${c.host}:443 -servername ${c.host} </dev/null 2>/dev/null | grep -E "Protocol|Cipher"`),
  ],
  "headers.cache-policy": (c) => [...hdr("Cache-Control", "private, no-cache", c), S("Nội dung công khai, ít đổi (ví dụ tài nguyên tĩnh)", "http", "Cache-Control: public, max-age=3600"), S("Kiểm tra", "bash", curlHeader(c.host, "cache-control"))],
  "config.debug-headers": (c) => [
    S("Nginx — ẩn header gỡ lỗi do ứng dụng phía sau gửi", "nginx", "proxy_hide_header X-Debug-Token;\nproxy_hide_header X-Debug-Token-Link;\nproxy_hide_header X-Runtime;\nproxy_hide_header X-Backend-Server;\nproxy_hide_header X-Generator;", "nginx"),
    S("Apache", "apache", "Header always unset X-Debug-Token\nHeader always unset X-Debug-Token-Link\nHeader always unset X-Runtime\nHeader always unset X-Backend-Server", "apache"),
    S("Symfony — tắt profiler ở production", "bash", "# .env.local trên máy chủ production\nAPP_ENV=prod\nAPP_DEBUG=0"),
    S("Kiểm tra: không còn dòng nào", "bash", curlHeader(c.host, "x-debug-token|x-debug-token-link|x-runtime|x-backend-server|x-server|x-host|x-generator")),
  ],
  "config.http-methods": (c) => [
    S("Nginx — chặn TRACE/TRACK", "nginx", "if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }", "nginx"),
    S("Apache", "apache", "TraceEnable off", "apache"),
    S("Express — chỉ cho phép phương thức cần thiết", "js", 'app.use((req, res, next) => (["GET", "HEAD", "OPTIONS", "POST"].includes(req.method) ? next() : res.sendStatus(405)));', "express"),
    S("Kiểm tra phương thức được công bố", "bash", `curl -si -X OPTIONS https://${c.host}/ | grep -iE "^(HTTP|allow):"`),
  ],
  "browser.form-targets": (c) => [
    S("Giới hạn nơi form được gửi tới bằng CSP", "http", "Content-Security-Policy: form-action 'self'"),
    S("Tìm các form mật khẩu đang trỏ ra ngoài (không sửa gì)", "bash", `curl -s https://${c.host}/ | grep -oiE "<form[^>]*action=[\"'][^\"']+[\"']" | head`),
  ],
  "cookies.prefix": (c) => [
    S("Dạng cookie phiên khuyến nghị", "http", "Set-Cookie: __Host-session=VALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
    S("Node.js / Express", "js", 'res.cookie("__Host-session", token, { httpOnly: true, secure: true, sameSite: "lax", path: "/" }); // không đặt domain', "express"),
    S("Kiểm tra", "bash", `curl -sI https://${c.host}/ | grep -i "^set-cookie:"`),
  ],

  // ---- header
  "headers.csp": (c) => [
    S("Triển khai thử ở chế độ chỉ báo cáo trước (không chặn gì, chỉ ghi nhận vi phạm)", "http", `Content-Security-Policy-Report-Only: ${RECOMMENDED.csp}`),
    ...hdr("Content-Security-Policy", RECOMMENDED.csp, c),
    S("Kiểm tra", "bash", curlHeader(c.host, "content-security-policy|content-security-policy-report-only")),
  ],
  "headers.frame-protection": (c) => [...hdr("X-Frame-Options", RECOMMENDED.xfo, c), S("Hoặc dùng CSP (ưu tiên)", "http", "Content-Security-Policy: frame-ancestors 'none'"), S("Kiểm tra", "bash", curlHeader(c.host, "x-frame-options|content-security-policy"))],
  "headers.x-content-type-options": (c) => [...hdr("X-Content-Type-Options", RECOMMENDED.xcto, c), S("Kiểm tra", "bash", curlHeader(c.host, "x-content-type-options"))],
  "headers.cross-origin-isolation": (c) => [
    S("Header khuyến nghị (thử kỹ trước vì COEP có thể làm hỏng tài nguyên bên thứ ba)", "http", "Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Resource-Policy: same-origin"),
    ...hdr("Cross-Origin-Opener-Policy", "same-origin", c),
    S("Kiểm tra", "bash", curlHeader(c.host, "cross-origin-opener-policy|cross-origin-resource-policy|cross-origin-embedder-policy")),
  ],
  "headers.charset": (c) => [S("Nginx", "nginx", "charset utf-8;", "nginx"), S("Apache", "apache", "AddDefaultCharset UTF-8", "apache"), S("HTML (dòng đầu trong <head>)", "html", '<meta charset="utf-8">'), S("Kiểm tra", "bash", curlHeader(c.host, "content-type"))],
  "headers.broken": (c) => [S("Xem lại các header bảo mật đang gửi", "bash", `curl -sI https://${c.host}/ | grep -iE "^(content-security-policy|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy):"`)],
  "headers.deprecated": (c) => [
    S("Nginx — ẩn header do ứng dụng phía sau gửi", "nginx", "proxy_hide_header Public-Key-Pins;\nproxy_hide_header Public-Key-Pins-Report-Only;\nproxy_hide_header Expect-CT;\nproxy_hide_header Feature-Policy;", "nginx"),
    S("Apache", "apache", "Header always unset Public-Key-Pins\nHeader always unset Public-Key-Pins-Report-Only\nHeader always unset Expect-CT\nHeader always unset Feature-Policy", "apache"),
    S("Cloudflare", "text", "Rules → Transform Rules → Modify Response Header → thêm các thao tác “Remove” cho từng header ở trên.", "cloudflare"),
    S("Kiểm tra: không còn dòng nào", "bash", curlHeader(c.host, "public-key-pins|public-key-pins-report-only|expect-ct|feature-policy")),
  ],
  "privacy.referrer-policy": (c) => [...hdr("Referrer-Policy", RECOMMENDED.referrer, c), S("Kiểm tra", "bash", curlHeader(c.host, "referrer-policy"))],
  "privacy.permissions-policy": (c) => [...hdr("Permissions-Policy", RECOMMENDED.permissions, c), S("Kiểm tra", "bash", curlHeader(c.host, "permissions-policy"))],

  // ---- trình duyệt
  "browser.mixed-content": (c) => [
    S("Tìm mọi tham chiếu http:// trong mã nguồn của bạn (không sửa gì)", "bash", `grep -rnE "(src|href|url)\\(?=?[\\"']?http://" --include="*.html" --include="*.js" --include="*.css" --include="*.jsx" --include="*.tsx" . 2>/dev/null | grep -v "w3.org" | head -40`),
    S("Biện pháp tạm thời: trình duyệt tự nâng cấp http:// thành https://", "http", "Content-Security-Policy: upgrade-insecure-requests"),
    S("Kiểm tra", "bash", `curl -s https://${c.host}/ | grep -oE "(src|href)=[\\"']http://[^\\"' ]+" | head`),
  ],
  "browser.third-party-integrity": () => [
    S("Tính mã băm SRI của file (thay URL bằng file bạn đang nhúng)", "bash", "curl -s https://cdn.example.com/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A"),
    S("Thêm vào thẻ script (thay HASH bằng kết quả ở trên)", "html", '<script src="https://cdn.example.com/lib.min.js"\n        integrity="sha384-HASH"\n        crossorigin="anonymous"></script>'),
  ],
  "browser.cors": () => [
    S("Node.js / Express — chỉ cho phép đúng nguồn của bạn", "js", `import cors from "cors";\napp.use(cors({\n  origin: ["https://app.example.com"], // thay bằng danh sách nguồn thật sự cần\n  credentials: true,\n}));\n// KHÔNG dùng origin: "*" cùng credentials, và không phản chiếu nguyên Origin của request.`, "express"),
    S("Nginx", "nginx", 'add_header Access-Control-Allow-Origin "https://app.example.com" always;\nadd_header Vary "Origin" always;', "nginx"),
  ],

  // ---- cookie
  "cookies.flags": (c) => [
    S("Nginx (1.19.3+) — thêm cờ cho mọi cookie do ứng dụng phía sau đặt", "nginx", "proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;", "nginx"),
    S("Apache (mod_headers)", "apache", 'Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"', "apache"),
    S("Dạng header chuẩn", "http", "Set-Cookie: session=VALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
    S("Kiểm tra", "bash", `curl -sI https://${c.host}/ | grep -i "^set-cookie:"`),
  ],
  "cookies.cache-control-sensitive": (c) => [...hdr("Cache-Control", "no-store", c), S("Kiểm tra", "bash", curlHeader(c.host, "cache-control"))],

  // ---- lộ thông tin
  "exposure.secrets": () => [
    S("Bước 1 — THU HỒI/XOAY khoá ngay ở nhà cung cấp (khoá đã công khai thì coi như đã lộ)", "text", "Đăng nhập dịch vụ phát hành khoá → vô hiệu hoá khoá cũ → tạo khoá mới → chỉ dùng khoá mới ở phía máy chủ."),
    S("Bước 2 — tìm khoá còn sót trong mã nguồn và lịch sử Git (không sửa gì)", "bash", 'git grep -nIE "(sk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|xox[bap]-)" $(git rev-list --all | head -50) | head -30'),
    S("Bước 3 — đưa khoá vào biến môi trường phía máy chủ", "bash", "# .env (đã thêm vào .gitignore, KHÔNG commit)\nAPI_KEY=gia-tri-moi\n# chỉ biến bắt đầu NEXT_PUBLIC_/VITE_/REACT_APP_ mới bị đóng gói vào trình duyệt: đừng đặt bí mật ở đó"),
  ],
  "exposure.public-config": () => [
    S("Kiểm tra biến nào đang bị đóng gói vào trình duyệt", "bash", 'grep -rnE "^(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)" .env* 2>/dev/null | sed "s/=.*/=…/"'),
    S("Quy tắc", "text", "Mọi biến NEXT_PUBLIC_/VITE_/REACT_APP_ đều công khai. Khoá thật sự bí mật phải ở phía máy chủ (API route/Server Action)."),
  ],
  "exposure.source-maps": (c) => [
    S("Nginx — chặn file .map", "nginx", "location ~* \\.map$ { return 404; }", "nginx"),
    S("Apache", "apache", '<FilesMatch "\\.map$">\n  Require all denied\n</FilesMatch>', "apache"),
    S("Vite", "js", "// vite.config.js\nexport default { build: { sourcemap: false } };"),
    S("Webpack", "js", "// webpack.config.js\nmodule.exports = { devtool: false };"),
    S("Kiểm tra: phải trả về 404/403", "bash", `curl -sI https://${c.host}/PATH/TO/main.js.map | head -1   # thay bằng đường dẫn .map thật`),
  ],
  "exposure.robots-txt": (c) => [S("robots.txt tối giản (đừng liệt kê đường dẫn nhạy cảm — ai cũng đọc được)", "text", `User-agent: *\nAllow: /\nSitemap: https://${c.host}/sitemap.xml`), S("Kiểm tra", "bash", `curl -s https://${c.host}/robots.txt | head -20`)],
  "exposure.sitemap-xml": (c) => [S("sitemap.xml tối giản", "xml", `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>https://${c.host}/</loc></url>\n</urlset>`), S("Kiểm tra", "bash", `curl -sI https://${c.host}/sitemap.xml | head -3`)],
  "exposure.security-txt": (c) => {
    const expires = new Date(c.now.getTime() + 365 * 86_400_000).toISOString().replace(/\.\d+Z$/, "Z");
    return [
      S("Tạo file .well-known/security.txt (thay địa chỉ email liên hệ thật)", "bash", `mkdir -p .well-known\ncat > .well-known/security.txt <<'EOF'\nContact: mailto:security@${c.host.replace(/^www\./, "")}\nExpires: ${expires}\nPreferred-Languages: vi, en\nCanonical: https://${c.host}/.well-known/security.txt\nEOF`),
      S("Kiểm tra sau khi triển khai", "bash", `curl -s https://${c.host}/.well-known/security.txt`),
    ];
  },
  "exposure.outdated-libraries": () => [
    S("Dự án npm: xem thư viện nào lỗi thời / có lỗ hổng đã biết", "bash", "npm outdated\nnpm audit"),
    S("Cập nhật một thư viện cụ thể (thay tên), rồi chạy lại kiểm thử", "bash", "npm install TEN_THU_VIEN@latest"),
    S("Thư viện nhúng qua CDN", "text", "Đổi số phiên bản trong URL của thẻ <script> sang bản mới nhất còn được hỗ trợ, rồi tính lại mã SRI (xem luật toàn vẹn script)."),
  ],
  "exposure.subdomain-takeover": (c) => [
    S("Xem bản ghi DNS đang trỏ tới dịch vụ đã xoá", "bash", `dig +short CNAME ${c.host}\ndig +short ${c.host}`),
    S("Cách xử lý", "text", "Xoá bản ghi CNAME/A của tên miền con này trong trình quản lý DNS, HOẶC tạo lại tài nguyên ở dịch vụ đích để không ai khác chiếm được."),
  ],
  "exposure.error-page-disclosure": (c) => [
    S("Nginx", "nginx", "server_tokens off;\nautoindex off;\nerror_page 404 /404.html;\nerror_page 500 502 503 504 /50x.html;", "nginx"),
    S("Apache", "apache", "ServerTokens Prod\nServerSignature Off\nOptions -Indexes", "apache"),
    S("Node.js / Express", "bash", "NODE_ENV=production node server.js   # chế độ production ẩn stack trace", "express"),
    S("Django", "text", "# settings.py\nDEBUG = False\nALLOWED_HOSTS = [\"" + c.host + "\"]"),
    S("Laravel", "bash", "# .env\nAPP_DEBUG=false\nAPP_ENV=production\nphp artisan config:cache"),
    S("PHP", "ini", "; php.ini\ndisplay_errors = Off\nlog_errors = On\nexpose_php = Off"),
    S("Spring Boot", "ini", "# application.properties\nserver.error.whitelabel.enabled=false\nserver.error.include-stacktrace=never\nserver.error.include-message=never"),
    S("Kiểm tra: trang 404 không còn chi tiết kỹ thuật", "bash", `curl -s https://${c.host}/khong-ton-tai-$RANDOM | head -20`),
  ],
  "exposure.internal-references": () => [
    S("Tìm địa chỉ nội bộ trong bản build (không sửa gì)", "bash", 'grep -rnE "(\\b10\\.[0-9]+\\.[0-9]+\\.[0-9]+|192\\.168\\.[0-9]+\\.[0-9]+|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9]+\\.[0-9]+|localhost:[0-9]+|\\.internal\\b)" dist build .next out public 2>/dev/null | head -30'),
    S("Quy tắc", "text", "Gọi dịch vụ nội bộ từ phía máy chủ, không từ mã chạy trong trình duyệt; đặt địa chỉ qua biến môi trường theo từng môi trường."),
  ],
  "exposure.html-comments": (c) => [
    S("Xem các bình luận HTML đang công khai", "bash", `curl -s https://${c.host}/ | grep -noE "<!--[^>]{0,200}-->" | head -30`),
    S("Loại bỏ bình luận khi build (Vite / webpack + html-minifier)", "bash", "npx html-minifier-terser --remove-comments --collapse-whitespace -o dist/index.html dist/index.html"),
  ],

  // ---- cấu hình
  "config.server-disclosure": (c) => [
    S("Nginx", "nginx", "server_tokens off;", "nginx"),
    S("Apache", "apache", "ServerTokens Prod\nServerSignature Off", "apache"),
    S("Node.js / Express", "js", 'app.disable("x-powered-by");', "express"),
    S("Next.js", "ts", "// next.config.ts\nconst nextConfig = { poweredByHeader: false };\nexport default nextConfig;", "nextjs"),
    S("PHP", "ini", "; php.ini\nexpose_php = Off"),
    S("Kiểm tra", "bash", curlHeader(c.host, "server|x-powered-by|x-aspnet-version")),
  ],
  "config.suspicious-redirects": (c) => [S("Xem toàn bộ chuỗi chuyển hướng", "bash", `curl -sIL -o /dev/null -w "%{url_effective} -> %{http_code}\\n" http://${c.host}/ && curl -sIL http://${c.host}/ | grep -iE "^(HTTP|location)"`)],
  "config.dns-email-security": (c) => {
    const d = c.host.replace(/^www\./, "");
    return [
      S("SPF (TXT tại gốc tên miền) — chọn MỘT: nếu tên miền KHÔNG gửi email", "text", `Tên: ${d}\nLoại: TXT\nGiá trị: v=spf1 -all`),
      S("SPF — nếu có gửi email: thay include bằng nhà cung cấp của bạn", "text", `Tên: ${d}\nLoại: TXT\nGiá trị: v=spf1 include:_spf.google.com ~all   # ví dụ Google Workspace; chỉ MỘT bản ghi SPF cho mỗi tên miền`),
      S("DMARC (bắt đầu ở chế độ theo dõi, sau đó siết dần lên quarantine → reject)", "text", `Tên: _dmarc.${d}\nLoại: TXT\nGiá trị: v=DMARC1; p=none; rua=mailto:dmarc@${d}`),
      S("CAA — chỉ cho phép nhà cấp chứng chỉ bạn dùng", "text", `Tên: ${d}\nLoại: CAA\nGiá trị: 0 issue "letsencrypt.org"`),
      S("Kiểm tra bản ghi đã có hiệu lực", "bash", `dig +short TXT ${d}\ndig +short TXT _dmarc.${d}\ndig +short CAA ${d}\ndig +short DS ${d}   # trống nghĩa là chưa bật DNSSEC`),
    ];
  },
};

/** Luật chỉ mang tính thông tin hoặc không có lệnh khắc phục có ý nghĩa. Một luật mới phải thuộc FIXES hoặc nhóm này (test bắt buộc). */
export const FIX_EXEMPT = new Set(["config.technology", "config.auth-surface", "privacy.third-party-origins", "privacy.trackers"]);

const GENERIC_SUMMARY = "Làm theo các lệnh và cấu hình bên dưới, sau đó dùng lệnh “Kiểm tra” để xác nhận.";

/**
 * Gắn lệnh khắc phục vào mọi phát hiện đang lỗi (status === "fail"). Không đổi điểm số, không đổi fingerprint.
 * Khôi phục các lệnh không trùng nhãn với snippet sẵn có của luật.
 */
export function attachFixCommands(findings: Finding[], base: { host: string; platforms: Platform[]; now?: Date }): Finding[] {
  if (!HOST_OK.test(base.host)) return findings; // host lạ: không chèn vào lệnh shell
  const now = base.now ?? new Date();
  return findings.map((f) => {
    if (f.status !== "fail") return f;
    const fn = FIXES[f.ruleId];
    if (!fn) return f;
    const extra = fn({ host: base.host, platforms: base.platforms, finding: f, now });
    if (extra.length === 0) return f;
    const existing = f.remediation ?? { summary: GENERIC_SUMMARY, snippets: [] };
    const seen = new Set(existing.snippets.map((s) => s.label));
    const merged: Remediation = { ...existing, snippets: [...existing.snippets, ...extra.filter((s) => !seen.has(s.label))] };
    return { ...f, remediation: merged };
  });
}
