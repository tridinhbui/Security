# VibeSec

Dán một URL, nhận báo cáo bảo mật bằng tiếng Việt dễ hiểu. VibeSec chạy các kiểm tra **thụ động, không xâm lấn** (vài chục request GET thông thường), chấm điểm 0–100 và chỉ ra cách khắc phục cụ thể cho từng vấn đề.

> Điểm số là đánh giá cấu hình *từ bên ngoài*. Điểm cao không chứng minh website an toàn, điểm thấp cũng không chứng minh website đã bị xâm nhập.

**Chạy hoàn toàn trên Cloudflare:** Workers (Next.js 16 qua OpenNext) · D1 · Queues · Cron Triggers · Containers (bộ quét) · Turnstile (tuỳ chọn). Giao diện và toàn bộ nội dung báo cáo bằng tiếng Việt.

## Tính năng

- **38 kiểm tra** thuộc 7 nhóm: Bảo mật đường truyền, HTTP Header, Bảo mật trình duyệt, Cookie & phiên đăng nhập, Lộ thông tin, Cấu hình hệ thống, Quyền riêng tư. Danh sách đầy đủ: trang `/phuong-phap` (tự sinh từ bộ luật đang chạy).
- Điểm 0–100 có trọng số, hạng A–F, điểm theo nhóm, **tóm tắt**, **kế hoạch khắc phục** theo mức công sức (kèm điểm ước tính tăng thêm), so sánh giữa các lần quét, **xuất Markdown**.
- **Chế độ dễ hiểu** (tiêu đề dạng câu hỏi + giải thích thuật ngữ) và **chế độ kỹ thuật** (header gốc, URL, bằng chứng, ánh xạ OWASP Top 10, tài liệu tham khảo).
- Ví dụ cấu hình theo Next.js, Vercel, Cloudflare, Nginx, Apache, Express — **chỉ khi nhận diện chắc chắn**, không bịa cấu hình.
- Lịch sử quét, biểu đồ xu hướng, liên kết chia sẻ chỉ đọc (token 256-bit, chỉ lưu băm), xoá báo cáo, thời gian lưu trữ 7/30/90/365 ngày.
- Chế độ demo: chạy bộ luật thật trên một website mẫu, không cần quét website thật.

### Các kiểm tra chính

| Nhóm | Ví dụ |
|---|---|
| Đường truyền | HTTPS & chứng chỉ, hạn chứng chỉ, **độ mạnh khoá/thời hạn**, TLS 1.0/1.1, **HTTP/2**, HTTP→HTTPS, **www/không-www**, HSTS, form mật khẩu |
| Header | CSP (kể cả **data:/blob:, host công cộng dễ vượt CSP**), chống clickjacking, nosniff, header sai cú pháp, **COOP/CORP/COEP**, **charset** |
| Trình duyệt | Mixed content, SRI cho CDN, CORS (phản chiếu origin, `null`, wildcard + credentials) |
| Cookie | Secure/HttpOnly/SameSite, tiền tố `__Host-`, **thời hạn cookie phiên**, cache trang đăng nhập |
| Lộ thông tin | Khoá bí mật (mẫu riêng từng nhà cung cấp), biến môi trường công khai, source map, robots/sitemap/security.txt, **thư viện JS lỗi thời (CVE)**, **nguy cơ chiếm subdomain**, **trang lỗi lộ thông tin (stack trace, debug, directory listing)** |
| Cấu hình | Lộ phiên bản máy chủ, chuyển hướng đáng ngờ, SPF (`+all`, >10 lookup, nhiều bản ghi) / DMARC / CAA / **DNSSEC** / **MTA-STS** |
| Quyền riêng tư | Referrer-Policy, Permissions-Policy, bên thứ ba, **trình theo dõi/quảng cáo** (nhắc Nghị định 13/2023/NĐ-CP) |

## Kiến trúc

```
Trình duyệt ─► Worker (giao diện Next.js + API) ──► D1 (người dùng, phiên, quét, phát hiện, sự kiện, chia sẻ)
                │  POST /api/scans: chuẩn hoá URL → kiểm tra SSRF → tiền kiểm DNS (DoH) → INSERT hạn mức nguyên tử
                ▼
          Queue "vibesec-scans" ─► queue() ─► nhận việc trong D1 (idempotent)
                                       │ POST /scan (NDJSON: tiến trình, rồi báo cáo)
                                       ▼
                        Container "ScannerContainer" (Node: container/server.ts)
                        ghim DNS · kiểm tra TLS · ≤ 34 request/lần · danh sách chặn egress
          Cron */2 phút: gửi lại job lạc, đánh dấu job treo · Cron hằng giờ: xoá dữ liệu hết hạn
```

Vì sao bộ quét nằm trong Container? `fetch` của Workers không ghim được địa chỉ DNS, không đọc được chứng chỉ TLS, không thử được TLS cũ — đều là phần cốt lõi của chống SSRF và các luật TLS. Container chạy đúng mã Node mà 500+ test đang kiểm tra; nó **không có quyền vào DB và không giữ secret**.

| Lớp | Đường dẫn |
|---|---|
| Giao diện + API | `src/app`, `src/components` |
| Entry (fetch + queue + cron + class Container) | `worker/index.ts` |
| Bộ quét (Container) | `container/server.ts`, `container/Dockerfile` |
| Chống SSRF | `src/lib/ssrf/` |
| Thu thập (toàn bộ I/O) · Luật (thuần) · Chấm điểm | `src/lib/scanner/` |
| Hướng dẫn: kế hoạch, tóm tắt, OWASP, Markdown | `src/lib/guidance.ts` |
| Schema D1 · repository (kiểm soát quyền sở hữu) | `migrations/`, `src/lib/db/` |
| Xác thực | `src/lib/auth/` |
| Job (tạo quét, xử lý hàng đợi) | `src/lib/jobs/` |

Bundle của Worker không bao giờ import `node:http/tls/dns` — `npm run typecheck` biên dịch riêng `worker/` với kiểu của Workers nên import Node lọt vào sẽ làm hỏng build.

## Chạy ở máy local

Mỗi lệnh chạy riêng, **không dán kèm chú thích** (zsh không coi `#` là chú thích trong shell tương tác):

```bash
npm install
```
```bash
npm run gen-keys
```
Dán kết quả vào `.dev.vars` (mẫu: `.dev.vars.example`). Sau đó:
```bash
npm run db:migrate:local
```
Terminal 1 — bộ quét (không cần Docker):
```bash
npm run scanner
```
Terminal 2 — Worker + D1 + Queue + cron:
```bash
npm run preview
```
Mở `http://localhost:8787`. Chạy test: `npm test` (500+ test).

`.dev.vars` có `LOCAL_SCANNER_URL=http://127.0.0.1:8080` để Worker gửi việc tới `npm run scanner` thay vì Container (chỉ dùng cho dev, không đặt ở production). Nếu thấy `EADDRINUSE`, scanner đã chạy rồi (`curl localhost:8080/ready` trả `ok`). Dùng `preview`/`wrangler dev`, không dùng `next dev` (không chạy consumer Queue nên scan sẽ đứng ở "queued").

## Triển khai

```bash
npx wrangler login
npx wrangler d1 create vibesec
npx wrangler queues create vibesec-scans
npx wrangler queues create vibesec-scans-dlq
```
Dán `database_id` vào `wrangler.jsonc`, đặt `NEXT_PUBLIC_SITE_URL` trong `vars`, rồi:
```bash
npm run db:migrate
npx wrangler secret put DATA_ENCRYPTION_KEY
npx wrangler secret put IP_HASH_SECRET
npx wrangler secret put CRON_SECRET
npm run deploy
```
Cần gói Workers **Paid** (Containers, Queues, CPU cho băm mật khẩu) và Docker để dựng image khi deploy. Turnstile (tuỳ chọn): tạo widget, đặt `NEXT_PUBLIC_TURNSTILE_SITE_KEY` lúc build và secret `TURNSTILE_SECRET_KEY`.

Quan sát: Workers Logs bật sẵn (JSON có cấu trúc, không bao giờ ghi nội dung phản hồi). `GET /api/admin/metrics` (Bearer `CRON_SECRET`) trả độ sâu hàng đợi, tuổi job cũ nhất, số quét hoàn tất/lỗi/từ chối/chặn/giới hạn trong 1 giờ, tỉ lệ lỗi, p50/p95 độ trễ. Job lỗi sau 3 lần thử vào `vibesec-scans-dlq`.

## An toàn của bộ quét (SSRF & lạm dụng)

- Chỉ `http`/`https`, chỉ cổng 80/443, không chấp nhận thông tin đăng nhập trong URL; query/fragment bị bỏ trước khi lưu.
- IPv4/IPv6 được phân tích thành số (thập phân, hex, bát phân, rút gọn `127.1`, IPv4-mapped/NAT64/6to4/Teredo, dấu chấm cuối, dấu chấm toàn chiều rộng…) rồi đối chiếu loopback, RFC 1918, CGNAT, link-local/metadata, multicast, dải dành riêng. Tên nội bộ bị từ chối trước khi tra DNS.
- **Hai lần kiểm tra DNS:** Worker tiền kiểm qua DoH (từ chối sớm); Container tra lại, yêu cầu **mọi** kết quả đều công khai (kết quả lẫn bị từ chối) và **ghim** socket vào đúng các địa chỉ đó — không tra lần hai nên DNS rebinding không đổi được sang IP riêng tư.
- Mỗi bước chuyển hướng được kiểm tra lại; tối đa 5 lần, phát hiện vòng lặp. Mỗi lần quét ≤ 34 request, ≤ 8 MB, ≤ 70 giây; mỗi request có trần byte và timeout cứng; `Accept-Encoding: identity`.
- **Lớp hạ tầng:** class Container đặt `deniedHosts` cho dải riêng tư/loopback/metadata. Cloudflare áp dụng cho HTTP:80; với 443 phải bật `interceptHttps` — khi đó chứng chỉ máy chủ bị thay bằng CA của Cloudflare và phá việc kiểm tra TLS, nên cố ý để tắt; cổng 443 dựa vào kiểm tra trong mã + ghim DNS.
- Theo tài khoản: số lượt chạy song song, hạn mức theo giờ/ngày; theo băm IP và **theo website đích** (để VibeSec không bị dùng làm công cụ tấn công một site) — thực thi trong **một câu `INSERT … SELECT … WHERE` nguyên tử** trên D1. Nhiều lần quét địa chỉ bị chặn (mặc định 5/giờ) → khoá tài khoản 24 giờ.
- Định danh `VibeSecBot/1.0`. Không lưu nội dung phản hồi; khoá bí mật bị che ngay khi phát hiện; giá trị cookie bị loại bỏ; header gốc được mã hoá AES-256-GCM; IP chỉ lưu dạng HMAC.

**Ngoài phạm vi có chủ đích:** đoán mật khẩu, vượt xác thực, payload SQLi/XSS, fuzzing, quét cổng, dò `/.env` hay `/.git`. Nếu sau này thêm kiểm tra nâng cao, bắt buộc xác minh quyền sở hữu tên miền trước.

## Xác thực & cách ly dữ liệu

D1 **không có row-level security** nên quyền sở hữu được thực thi trong `src/lib/db/repo.ts`: mọi hàm đọc/sửa dữ liệu người dùng đều nhận `userId` trong mệnh đề `WHERE` (test phủ việc đọc chéo, xoá chéo, thu hồi liên kết, tra phát hiện của người khác). Liên kết chia sẻ công khai đi qua băm token và không bao giờ lộ header gốc.

Xác thực tự xây: scrypt (N=2¹⁵, r=8, p=3), token phiên ngẫu nhiên 256-bit chỉ lưu băm SHA-256, cookie `HttpOnly; Secure; SameSite=Lax` (`__Host-` ở production), hạn trượt 30 ngày, báo lỗi giống nhau cho email lạ và sai mật khẩu (kèm băm giả để cân bằng thời gian), giới hạn đăng nhập sai theo email và IP, giới hạn đăng ký theo IP, Turnstile tuỳ chọn, kiểm tra same-origin (CSRF) trên mọi route ghi.

## Thêm một luật mới

1. Viết `Rule` (`id`, `title`, `category`, `run(obs) → Finding[]`) trong `src/lib/scanner/rules/*.ts` và thêm vào mảng xuất của file đó. Nội dung hiển thị phải bằng tiếng Việt.
2. Thêm mục vào `EFFORT` (và `OWASP_MAP` nếu có) trong `src/lib/guidance.ts` và `PLAIN_TITLES` trong `src/lib/beginner.ts` — test sẽ báo nếu thiếu.
3. Viết test; fixture `baseline()` (website cứng cáp) vẫn phải cho ra 0 lỗi. Test “100% tiếng Việt” sẽ chặn chữ Anh lọt vào phần diễn giải.

Chỉ gán Nghiêm trọng/Cao khi bằng chứng tự nó chứng minh vấn đề; heuristic dùng độ tin cậy trung bình/thấp (cũng giảm mức trừ điểm) và không vượt Trung bình. Chữ ký dễ khớp nhầm phải được giới hạn phạm vi (ví dụ stack trace chỉ tìm trong phản hồi của đường dẫn *không tồn tại*).

## Đã kiểm chứng và chưa kiểm chứng

Đã kiểm chứng: 513 test (SSRF, chuyển hướng, DNS rebinding, từng luật, chấm điểm, repository D1 trên SQLite thật gồm hạn mức nguyên tử, xác thực, xử lý job với engine thật, giao thức NDJSON của Container, nội dung hướng dẫn), typecheck cả hai runtime, build OpenNext, `wrangler deploy --dry-run`, toàn bộ Worker chạy dưới `wrangler dev` (migration, đăng ký/đăng nhập, CSRF, throttle, cách ly dữ liệu, queue + retry, metrics, giao diện trình duyệt), và bộ quét thật trên `example.com` / `tuhoctaichinh.org` (38 luật, ~22 request, ~3 giây).

**Chưa kiểm chứng:** dựng và chạy image Container (máy dev không có Docker) nên chưa thấy đường Worker→Container chạy thật khi deploy; lần deploy thật; Turnstile. Hãy quét thử một website của bạn ngay sau lần deploy đầu.

## Hạn chế đã biết

- Phát hiện TLS 1.0/1.1 chỉ báo khi bắt tay thành công (không báo sai, có thể bỏ sót máy chủ yếu).
- Danh sách thư viện lỗi thời chỉ gồm các thư viện phổ biến và CVE nổi tiếng; dùng thêm `npm audit`/Dependabot cho kiểm tra đầy đủ. Phiên bản đọc từ tên file/URL/chú thích đầu file nên độ tin cậy ở mức vừa.
- Phát hiện bí mật cố ý thận trọng (chỉ mẫu riêng từng nhà cung cấp); không thấy gì ≠ không có.
- Chỉ xem trang bạn nhập, ≤ 6 script cùng origin, ≤ 3 source map, một trang đăng nhập, một đường dẫn 404 và phiên bản www/không-www; không bao giờ vào khu vực đã đăng nhập.
- Chưa có xác minh email và quên mật khẩu (cần Cloudflare Email Service); Turnstile + giới hạn đăng ký theo IP là biện pháp chống lạm dụng hiện tại.
- CSP của chính ứng dụng cho phép `'unsafe-inline'` cho script khởi động của Next.js; CSP dùng nonce sẽ chặt hơn.
