# VIBESEC — Audit nội dung, tiếng Việt, khả năng dùng cho người mới & độ chính xác bảo mật

Ngày: 2026-10-18 · Nhánh: `audit/content-usability-security` (từ `main` @ `c904e2b`) · Người thực hiện: Claude (Opus 5.5) cùng một agent phụ kiểm chứng độ chính xác bằng fixture.

> **Cách đọc báo cáo này.** Mọi chỗ ghi **“đã kiểm chứng”** đều có test chạy được trong repo hoặc thao tác thật trên trình duyệt (ghi rõ ở cột bằng chứng). Những chỗ ghi **“mô phỏng chuyên gia”** là đánh giá của người rà soát đóng vai người dùng, **không phải** nghiên cứu người dùng thật. Chưa có người dùng thật nào tham gia đợt này.

## 0. Tóm tắt

| Hạng mục | Kết quả |
|---|---|
| Số kiểm tra thực tế | **63 luật** (48 cơ bản + 15 nâng cao `adv.*`), quét nhanh chạy 47 luật. Yêu cầu nói “39 checks” nhưng không có cách đếm nào trong repo cho ra 39, nên báo cáo này kiểm toàn bộ 63. |
| Lỗi độ chính xác **P0 đã sửa** | 3: website chỉ có HTTP được **90/A** ở quét nhanh; website không kết nối được bị chấm **0/F** và lưu cache 6 giờ; website trên tên miền con của nền tảng (`*.vercel.app`, `*.workers.dev`…) bị báo thiếu SPF/DMARC/CAA/DNSSEC **của chính nền tảng** và được hướng dẫn thêm bản ghi DNS mà họ không có quyền thêm. |
| Lỗi **P1 đã sửa** | 12, gồm: một lỗi CSP bị trừ điểm hai lần, không có HTTPS mà vẫn đạt hạng C, header lặp do proxy bị báo sai, cookie của CDN bị coi là rò rỉ phiên (mức Cao, kéo trần 79), form React không ghi `method` bị trừ 30 điểm, `security.txt` bị báo “chưa công bố” khi chỉ là hết thời gian chờ, trang chặn của tường lửa (403/“Just a moment…”) bị chấm điểm như website thật, khoá `sb_secret_` của Supabase không bị phát hiện… (xem §3) |
| Chưa sửa (có chủ đích) | Bảng §3.3: 8 mục P2 và các thay đổi cần chủ sản phẩm quyết định |
| Kiểm thử | `npm run typecheck` sạch · **1116 test** đạt (trước đợt này 1073; thêm 43 test, trong đó 21 hồi quy độ chính xác) · `build:cf` và `wrangler deploy --dry-run` thành công · E2E trên trình duyệt thật: desktop, 768px, 390px, 375px |
| Không làm | Không khai thác, không fuzzing; chỉ quét thụ động **chính website VibeSec** (`security.tridinhbui0901.workers.dev`), cộng một lần `example.com` (tên miền dành cho ví dụ) trước khi chuyển sang dùng site của mình. Không deploy. |

## 1. Phạm vi & phương pháp

1. **Đọc mã:** 63 luật trong `src/lib/scanner/rules/*`, chấm điểm (`score.ts`), quét nhanh (`quick.ts`, `jobs/quick-scan.ts`), thu thập (`collect-core.ts`), giải thích (`explain*.ts`, `beginner.ts`, `feynman.ts`, `matmat.ts`) và các màn hình trong `src/app` / `src/components`.
2. **Kiểm chứng độ chính xác bằng fixture:** `baseline()` (website mẫu cấu hình chuẩn) rồi đổi từng chi tiết (header lặp, CSP nhiều chính sách, cookie CDN, DNS lỗi, HTTPS lỗi, trang 403…) và chạy chính các luật cùng hàm chấm điểm. Không có request mạng thật.
3. **Dùng sản phẩm thật** trên dev server (cây mã của nhánh này) trong trình duyệt: trang chủ → quét thử → đọc kết quả → mở giải thích → lọc → chép hướng dẫn; báo cáo đầy đủ (`/demo`); 375/390/768px và desktop.
4. **Ảnh chụp:** `docs/audit-screenshots/` (before = production lúc audit, after = nhánh này). Ảnh ở độ rộng điện thoại không lưu được thành tệp: Chrome headless trên macOS không thu nhỏ cửa sổ dưới khoảng 500px, nên kiểm tra mobile được làm trong trình duyệt tích hợp bằng số đo DOM (tràn ngang, kích thước chip) thay vì ảnh.
5. **Playwright:** không có trong dự án và tôi không thêm phụ thuộc mới; dùng trình duyệt tích hợp + Chrome headless thay thế.

## 2. Kiểm kê 63 kiểm tra

“Tham chiếu trong test” = số lần mã luật xuất hiện trong các tệp test của scanner (mọi luật đều có ít nhất một test, vì `explain-quality.test.ts` chạy đủ 63 luật × từng biến thể).

| Mã luật | Tên | Nhóm | Quét | Có trong quét nhanh | Tham chiếu trong test |
|---|---|---|---|---|---|
| `tls.https-available` | HTTPS hoạt động với chứng chỉ hợp lệ | Transport Security | cơ bản | có | 5 |
| `tls.certificate-expiry` | Chứng chỉ chưa sắp hết hạn | Transport Security | cơ bản | có | 3 |
| `tls.certificate-strength` | Chứng chỉ dùng khoá đủ mạnh | Transport Security | cơ bản | — | 4 |
| `tls.protocol-version` | Chỉ chấp nhận phiên bản TLS hiện đại | Transport Security | cơ bản | — | 3 |
| `tls.http2` | Hỗ trợ HTTP/2 | Transport Security | cơ bản | — | 2 |
| `tls.http-to-https-redirect` | HTTP được chuyển hướng sang HTTPS | Transport Security | cơ bản | có | 10 |
| `tls.www-consistency` | Phiên bản www / không-www cũng an toàn | Transport Security | cơ bản | có | 2 |
| `tls.hsts` | HTTP Strict Transport Security (HSTS) | Transport Security | cơ bản | có | 17 |
| `tls.insecure-login-form` | Form đăng nhập được bảo vệ bằng HTTPS | Transport Security | cơ bản | có | 4 |
| `headers.csp` | Content-Security-Policy | Headers | cơ bản | có | 22 |
| `headers.frame-protection` | Chống clickjacking (X-Frame-Options / frame-ancestors) | Headers | cơ bản | có | 7 |
| `headers.x-content-type-options` | X-Content-Type-Options | Headers | cơ bản | có | 6 |
| `headers.broken` | Các header bảo mật viết đúng cú pháp | Headers | cơ bản | có | 18 |
| `headers.cross-origin-isolation` | Cô lập tiến trình cross-origin (COOP / CORP / COEP) | Headers | cơ bản | có | 2 |
| `headers.charset` | Khai báo bảng mã ký tự | Headers | cơ bản | — | 2 |
| `headers.deprecated` | Không còn dùng header đã bị loại bỏ | Headers | cơ bản | có | 3 |
| `browser.mixed-content` | Không có nội dung hỗn hợp (mixed content) | Browser Security | cơ bản | có | 3 |
| `browser.third-party-integrity` | Script CDN bên thứ ba có Subresource Integrity | Browser Security | cơ bản | có | 3 |
| `browser.cors` | Cấu hình CORS | Browser Security | cơ bản | có | 9 |
| `cookies.flags` | Cookie dùng Secure, HttpOnly và SameSite | Cookies & Sessions | cơ bản | có | 11 |
| `cookies.cache-control-sensitive` | Trang nhạy cảm không bị lưu đệm (cache) | Cookies & Sessions | cơ bản | — | 3 |
| `exposure.internal-references` | Không lộ địa chỉ mạng nội bộ | Exposure | cơ bản | có | 3 |
| `exposure.html-comments` | Bình luận HTML không lộ thông tin nhạy cảm | Exposure | cơ bản | có | 3 |
| `exposure.secrets` | Không có bí mật hiển nhiên trong HTML/JavaScript công khai | Exposure | cơ bản | có | 8 |
| `exposure.public-config` | Giá trị môi trường phía trình duyệt | Exposure | cơ bản | có | 4 |
| `exposure.source-maps` | Source map không công khai | Exposure | cơ bản | — | 3 |
| `exposure.robots-txt` | robots.txt | Exposure | cơ bản | có | 4 |
| `exposure.sitemap-xml` | sitemap.xml | Exposure | cơ bản | có | 4 |
| `exposure.security-txt` | security.txt (liên hệ báo cáo lỗ hổng) | Exposure | cơ bản | có | 12 |
| `exposure.outdated-libraries` | Thư viện JavaScript không nằm trong danh sách lỗ hổng đã biết | Exposure | cơ bản | có | 2 |
| `exposure.subdomain-takeover` | Không có dấu hiệu có thể bị chiếm quyền tên miền (subdomain takeover) | Exposure | cơ bản | có | 3 |
| `exposure.error-page-disclosure` | Trang lỗi không lộ thông tin nội bộ | Exposure | cơ bản | có | 3 |
| `config.server-disclosure` | Không để lộ phiên bản máy chủ và framework | Configuration | cơ bản | có | 5 |
| `config.technology` | Công nghệ được nhận diện | Configuration | cơ bản | — | 4 |
| `config.suspicious-redirects` | Hành vi chuyển hướng | Configuration | cơ bản | có | 3 |
| `config.dns-email-security` | Metadata bảo mật DNS & email | Configuration | cơ bản | có | 13 |
| `config.auth-surface` | Cấu hình xác thực quan sát được từ bên ngoài | Configuration | cơ bản | — | 3 |
| `privacy.referrer-policy` | Referrer-Policy | Privacy | cơ bản | có | 10 |
| `privacy.permissions-policy` | Permissions-Policy | Privacy | cơ bản | có | 2 |
| `privacy.third-party-origins` | Request tới bên thứ ba | Privacy | cơ bản | — | 2 |
| `privacy.trackers` | Trình theo dõi và quảng cáo bên thứ ba | Privacy | cơ bản | — | 2 |
| `tls.hsts-preload` | HSTS đủ điều kiện danh sách preload | Transport Security | cơ bản | có | 4 |
| `tls.cipher-suite` | Bộ mã hoá TLS hiện đại | Transport Security | cơ bản | có | 3 |
| `headers.cache-policy` | Chính sách bộ nhớ đệm của trang HTML | Headers | cơ bản | có | 3 |
| `config.debug-headers` | Không lộ header gỡ lỗi hoặc địa chỉ nội bộ | Configuration | cơ bản | có | 3 |
| `config.http-methods` | Phương thức HTTP được công bố | Configuration | cơ bản | — | 3 |
| `browser.form-targets` | Form mật khẩu chỉ gửi về chính website | Browser Security | cơ bản | có | 3 |
| `cookies.prefix` | Cookie phiên dùng tiền tố __Host-/__Secure- | Cookies & Sessions | cơ bản | có | 4 |
| `adv.csp-analysis` | Phân tích sâu chính sách CSP | Headers | đầy đủ | có | 7 |
| `adv.shared-cache-leak` | Cookie phiên không bị cache dùng chung giữ lại | Cookies & Sessions | đầy đủ | có | 6 |
| `adv.cookie-scope` | Phạm vi và vòng đời cookie hợp lý | Cookies & Sessions | đầy đủ | có | 1 |
| `adv.supply-chain` | Chuỗi cung ứng script bên thứ ba | Browser Security | đầy đủ | có | 3 |
| `adv.dom-xss-flow` | Luồng dữ liệu nguy hiểm trong JavaScript (DOM XSS) | Browser Security | đầy đủ | — | 4 |
| `adv.postmessage` | Xử lý postMessage an toàn | Browser Security | đầy đủ | — | 2 |
| `adv.web-storage-secrets` | Không lưu token đăng nhập trong localStorage | Browser Security | đầy đủ | — | 2 |
| `adv.endpoint-map` | Bản đồ endpoint lộ trong mã trang | Exposure | đầy đủ | — | 1 |
| `adv.graphql-surface` | GraphQL không để lộ introspection | Exposure | đầy đủ | — | 1 |
| `adv.redirect-chain` | Chuỗi chuyển hướng gọn và an toàn | Transport Security | đầy đủ | có | 1 |
| `adv.header-consistency` | Header bảo mật nhất quán giữa các trang | Headers | đầy đủ | có | 1 |
| `adv.spf-deep` | SPF chặt và hợp lệ | Configuration | đầy đủ | có | 3 |
| `adv.dmarc-deep` | DMARC được thực thi đầy đủ | Configuration | đầy đủ | có | 1 |
| `adv.certificate-hygiene` | Vệ sinh chứng chỉ TLS | Transport Security | đầy đủ | có | 1 |
| `adv.form-method` | Form mật khẩu không dùng GET | Browser Security | đầy đủ | có | 2 |

## 3. Độ chính xác: kết quả kiểm chứng

### 3.1 Đã sửa (kèm test hồi quy trong `src/lib/scanner/__tests__/audit-regressions.test.ts`, trừ khi ghi khác)

| ID | Luật / tệp | Đầu vào (fixture) | Trước → Sau | Mức |
|---|---|---|---|---|
| A1 | `quick.ts` | HTTPS lỗi kết nối, HTTP trả trang bình thường | **90/A** (mọi kiểm tra HTTPS im lặng) → **không chấm điểm**, thông báo “nếu chưa có HTTPS thì bật HTTPS trước; nếu có thì thử lại” | P0 |
| U1 | `quick.ts`, `jobs/quick-scan.ts` | Không kết nối được cả HTTPS lẫn HTTP | **0/F, lưu cache 6 giờ** (biến “chưa kiểm tra được” thành “lỗi”) → lỗi 502 có hướng dẫn, **không lưu cache** (test trong `jobs/__tests__/quick-scan.test.ts`) | P0 |
| D1 | `collect-core.ts`, `config.dns-email-security`, `platform-domain.ts` | `myapp.vercel.app`, `x.workers.dev`, `me.github.io` | Tra DNS của `vercel.app`/`workers.dev` và báo “chưa có CAA/DNSSEC” cho người dùng, kèm hướng dẫn thêm bản ghi họ không có quyền thêm → **không tra**, một mục “Tham khảo: không áp dụng”, không trừ điểm (dựa trên Public Suffix List; test `platform-domain.test.ts`) | P0 |
| D2 | `explain*.ts`, `fixes.ts`, `analyst.ts` | Quét `shop.example.com` | Giải thích và lệnh sửa nói “thêm SPF cho shop.example.com” trong khi luật tra `example.com` → dùng đúng tên miền đã tra (`dnsApex`) | P1 |
| S1 | `score.ts` | CSP có `'unsafe-inline'` | Trừ **2 lần** (headers.csp + adv.csp-analysis = −14) và chiếm 2/3 “việc nên làm trước” → mỗi **nguyên nhân gốc** trừ một lần (khoản nặng nhất), mục còn lại ghi “Cùng nguyên nhân với…”; danh sách ưu tiên không lặp. Áp dụng cho 6 cặp: CSP, form GET, chuỗi chuyển hướng, SPF, DMARC, hạn chứng chỉ, cookie+cache | P1 |
| A2/A3 | `coverage.ts`, `pipeline.ts` | HTTPS không ổn định / không đọc được TLS / không tra được DNS | **96/A** dù cả nhóm kiểm tra không có dữ liệu → trần điểm hạ xuống 90 và danh sách “Lần quét này chưa kiểm tra được…” (quét nhanh hiển thị ngay dưới điểm) | P1 |
| A4 | `exposure.ts` | `security.txt` hết thời gian chờ / 403 / 503 | “Chưa công bố security.txt” (lỗi) → “Chưa kiểm tra được” (unknown, không trừ điểm); robots/sitemap lỗi mạng không còn nói “không có” | P1 |
| A5 | `headers.ts` | `X-Frame-Options: SAMEORIGIN, SAMEORIGIN`; `nosniff, nosniff` (hai lớp proxy cùng thêm) | 2 lỗi “giá trị không hợp lệ” → hợp lệ (đúng HTML spec / Fetch spec); `DENY, SAMEORIGIN` vẫn bị báo | P1 |
| A6 | `headers.ts`, `advanced.ts` | Hai header CSP: một chặn script, một chỉ có `frame-ancestors` | “Trang có thể bị nhúng (clickjacking)” → đạt; CSP được đánh giá theo chính sách chặt nhất | P1 |
| A7 | `advanced.ts`, `hardening.ts`, `cookies.ts` | Trang được CDN cache kèm cookie `__cf_bm` / `NEXT_LOCALE` | **Cao** (kéo trần 79) + Trung bình → không báo; cookie phiên thật vẫn báo, mức **Trung bình** (chưa chứng minh bị phát lại) | P1 |
| A8 | `parse.ts`, `transport.ts`, `advanced.ts` | Form React có ô mật khẩu, **không ghi** `method` | 2 lỗi mức Cao (−30, ra 70/C) → một lỗi Trung bình, độ tin cậy thấp, giải thích “nếu JavaScript gửi bằng POST thì không sao”; `method="get"` ghi rõ vẫn mức Cao | P1 |
| A9 | `transport.ts` | Không có HTTPS (cổng 443 từ chối) | Mức Cao → tối đa **79/C** → mức **Nghiêm trọng**, tối đa 59 | P1 |
| A10 | `coverage.ts` | Trang chủ trả 403 / 429 / 503 / “Just a moment…” | Chấm điểm trang chặn của tường lửa (78/C với 6 lỗi giả) → **không chấm điểm**, hướng dẫn cho phép VibeSecBot rồi quét lại (cả quét nhanh, quét đầy đủ và quét lai) | P1 |
| A11 | `cookies.ts` | Cookie bị xoá khi đăng xuất (`Max-Age=0`); cookie phiên đặt ở bước chuyển hướng `http://` | Cookie đã xoá bị báo thiếu cờ; cookie phiên qua HTTP thuần bị bỏ sót → bỏ qua cookie đã xoá; đọc cả chuỗi chuyển hướng HTTP | P1 |
| H1 | `transport.ts`, `hardening.ts` | Website đuôi `.dev` / `.app` (cả đuôi nằm trong danh sách HSTS cài sẵn của trình duyệt) | “HTTP không chuyển hướng” (−7), “Thiếu HSTS”, “Chưa preload” → “Tham khảo”, không trừ điểm, giải thích vì sao trình duyệt không bao giờ mở `http://` | P1 |
| P1-1 | `secrets.ts` | `sb_secret_…` trong JavaScript công khai | Không phát hiện → **Nghiêm trọng**; `sb_publishable_` là công khai theo thiết kế (thông tin) | P1 |

Cũng đã kiểm chứng **đúng** (không cần sửa): CSP `'unsafe-inline'` kèm nonce được coi là chặt (CSP3); HSTS chỉ có trên `http://` vẫn bị báo thiếu ở HTTPS; hai giá trị HSTS dùng giá trị đầu (RFC 6797); trang JSON không bị đòi CSP/XFO; tên header không phân biệt hoa thường.

Phiên bản bộ luật tăng `ENGINE_VERSION` 9 → 10 để kết quả cache cũ (chấm theo cách cũ) không bị dùng lại.

### 3.2 Ảnh hưởng thật trên chính website VibeSec (quét nhanh, cùng một website, trước/sau)

| | Trước (production) | Sau (nhánh này) |
|---|---|---|
| Điểm | 73/100, hạng C | 90/100, hạng A (trần quét nhanh) |
| “Nên làm trước” | 1. HTTP không chuyển sang HTTPS · 2. CSP còn yếu · 3. CSP có điểm yếu (cùng một lỗi) | 1. CSP còn yếu · 2. Header cô lập cross-origin · 3. security.txt |
| Lỗi giả | “HTTP không chuyển hướng” (đuôi `.dev` đã ép HTTPS), “Chưa có CAA”, “Chưa bật DNSSEC” (của `workers.dev`, không phải của VibeSec) | Ba mục này chuyển thành “Tham khảo” với lời giải thích; lỗi CSP thật vẫn đứng đầu |

Điểm tăng **không** có nghĩa website an toàn hơn; nó chỉ bỏ những khoản trừ quy sai cho chủ website. Dưới điểm luôn có dòng “Điểm chỉ phản ánh các mục VibeSec kiểm tra được từ bên ngoài, không phải chứng nhận website an toàn.”

### 3.3 Chưa sửa (báo để quyết định)

| ID | Vấn đề | Lý do chưa sửa | Đề xuất |
|---|---|---|---|
| A12 | SPF `~all`: luật cơ bản nói “đạt, kết thúc chặt chẽ”, luật sâu lại báo yếu; thiếu `all` không bị báo | Cần thống nhất định nghĩa “chặt” giữa hai luật | Một bộ phân tích SPF dùng chung |
| A13 | Trang 404 thử nghiệm trả 308 vẫn bị so header | Ít gặp | Chỉ so khi mã ≥ 400 |
| A14 | Không có cookie / không có tài nguyên ngoài vẫn hiện “Đạt” | Không sai, nhưng “không áp dụng” chính xác hơn | Hiện “Không áp dụng” |
| G1 | Báo cáo đầy đủ đã lưu chưa hiển thị danh sách “chưa kiểm tra được” (chỉ thấy trần điểm thấp hơn) | Cần cột mới trong DB | Lưu `stats.coverageGaps` khi lưu lượt quét |
| O1/O2 | OWASP Top 10 **2021** và ASVS 4.0.3 vẫn là khung tham chiếu (trang chủ ghi “OWASP Top 10 (2021)”) | Đổi khung ánh xạ cần người có chuyên môn duyệt (đã nêu trong `docs/SECURITY-CONTENT-AUDIT.md`) | Chuyển sang Top 10:2025 có bảng ánh xạ |
| SEV | `config.http-methods` TRACE mức Trung bình; `adv.certificate-hygiene` (hạn) Trung bình trong khi luật cơ bản là Thấp; `exposure.security-txt` thiếu là Thấp | Đổi mức nghiêm trọng đổi điểm của mọi người dùng | Duyệt cùng benchmark |
| T1 | Nhận biết “trang chặn” dựa trên mã 401/403/429/503 và vài tiêu đề quen thuộc; website cố ý trả 403 cho trang chủ sẽ không được chấm | Đánh đổi có chủ đích: thà không chấm còn hơn chấm sai | Cho người dùng chọn “vẫn chấm điểm” |
| T2 | Danh sách đuôi HSTS-preload là danh sách bảo thủ viết tay (`.app`, `.dev`, `.page`…) | Không có nguồn chính thức gọn nhẹ để nhúng | Đồng bộ định kỳ từ danh sách preload của Chromium |

## 4. Điểm số: có đáng tin không?

**Công thức** (công khai ở tab “Điểm & phạm vi”): 100 − Σ(trọng số mức độ × hệ số tin cậy); Nghiêm trọng 30 · Cao 15 · Trung bình 7 · Thấp 3 · Thông tin 0; tin cậy cao 1 · vừa 0,7 · thấp 0,4. Có Nghiêm trọng → tối đa 59; có Cao → tối đa 79. Trần 96 (quét đầy đủ) hoặc 90 (quét nhanh, chạm giới hạn, hoặc **thiếu dữ liệu ở một nhóm kiểm tra** — mới). Mục “tham khảo” và “chưa kiểm tra được” không bao giờ đổi điểm.

| Câu hỏi | Trả lời sau audit |
|---|---|
| Người dùng có hiểu vì sao được 70/100? | Có, nếu mở tab “Điểm & phạm vi” (từng khoản trừ, trần). Ở chế độ Dễ hiểu, điểm nay luôn đi kèm câu nói rõ phạm vi. |
| Hai website cùng điểm có cùng rủi ro? | **Không.** Ví dụ đã chạy: chỉ một lỗi CORS phản chiếu origin kèm cookie → 79/C; thiếu cả CSP, XFO, nosniff, Referrer-Policy, COOP/CORP, security.txt, CAA, DNSSEC → cũng 79/C. Vì vậy giao diện luôn đặt “Nên làm trước” (theo mức khẩn cấp) cạnh điểm, không để điểm đứng một mình. |
| Có tính trùng? | Có (10 cặp, xem §3.1 S1). Đã gộp 6 nguyên nhân gốc có cùng cấu hình; các cặp khác (vd. lộ phiên bản nginx ở header và ở trang lỗi) là hai chỗ lộ khác nhau nên giữ. |
| Header ít tác động có bị đánh nặng hơn rủi ro lớn? | Không: thiếu Permissions-Policy trừ 0; form mật khẩu gửi qua HTTP trừ 30 và kéo trần 59. Lệch duy nhất tìm thấy là “không có HTTPS” chỉ ra C — đã sửa (A9). |
| Đạt A nhưng vẫn có rủi ro lớn ngoài phạm vi? | **Có**, và không thể tránh với quét thụ động: phân quyền, logic nghiệp vụ, lỗi chèn mã thật, database. Giao diện ghi rõ ở dưới điểm, trong tab phạm vi và ở trang phương pháp. |

**Ba lớp trình bày** (đã có, được củng cố): *Tình trạng tổng quan* (điểm + câu phạm vi + số cần sửa/nên cải thiện/chưa kiểm tra) → *Việc nên làm trước* (tối đa 3, không lặp nguyên nhân) → *Hướng dẫn cụ thể* (từng mục: thấy gì → vì sao → hệ quả → mức chắc chắn → ai làm → các bước → kết quả đúng → lệnh tự kiểm tra lại).

## 5. Tiếng Việt & thuật ngữ

### 5.1 Đã sửa

| Vị trí | Trước | Vấn đề | Sau |
|---|---|---|---|
| Trang chủ, dòng nhỏ | `EXTERNAL ATTACK SURFACE SCANNER` | Tiếng Anh, thuật ngữ chuyên ngành | `KIỂM TRA BẢO MẬT WEBSITE · KHÔNG CẦN BIẾT KỸ THUẬT` |
| Trang chủ, tiêu đề | “Nhìn website như một attacker.” | “attacker” là tiếng Anh; người mới không biết mình nhận được gì | “Website của bạn đang hở chỗ nào?” |
| Trang chủ, mô tả | “…phân tích bề mặt tấn công công khai…” | Thuật ngữ “bề mặt tấn công” | “VibeSec nhìn website giống như một người lạ trên mạng, chỉ ra những chỗ cấu hình chưa an toàn, giải thích bằng tiếng Việt dễ hiểu và hướng dẫn sửa từng bước.” |
| Trang chủ, bước 2 | “Chín giai đoạn: phân giải, TLS, header, endpoint công khai…” | Liệt kê thuật ngữ, không nói lợi ích | “Chỉ đọc, không tấn công: … ổ khoá HTTPS, các “biển báo an toàn” website gửi cho trình duyệt (header), cookie, bản ghi email…” |
| Trang chủ | “Cần tài khoản miễn phí để chống lạm dụng.” | **Mâu thuẫn**: bấm quét lại vào trang “Không cần tài khoản” | “Quét nhanh không cần tài khoản. Tạo tài khoản miễn phí để quét đầy đủ và lưu lịch sử.” |
| Trang chủ, hình minh hoạ | “Đang quét… 38 / **41**” cạnh “**63** kiểm tra” | Số mâu thuẫn | Dùng đúng số luật thật |
| Ô nhập URL | “Nhập URL để quét (ví dụ: https://example.com)” | Bị cắt ở màn hình hẹp | “vd. tenmien.vn” |
| Quét nhanh, trạng thái | Đạt / Cảnh báo / **Lỗi** | Mọi cấu hình chưa tối ưu đều thành “Lỗi” (gây hoang mang); không có chỗ cho “chưa kiểm tra được” | **Cần sửa** (Trung bình trở lên) / **Nên cải thiện** (Thấp) / **Tham khảo** / **Chưa kiểm tra** / Đạt |
| Quét nhanh, tên nhóm | `CSP`, `CORS`, `HTTPS / SSL`, `SPF / DMARC / CAA`, `Header bảo mật` | Viết tắt trước, không có nghĩa | “Chính sách chặn mã lạ (CSP)”, “Quyền đọc dữ liệu từ website khác (CORS)”, “Ổ khoá HTTPS”, “Chống giả mạo email & tên miền (SPF / DMARC / CAA)”, “Biển báo an toàn cho trình duyệt (header)” |
| Lời chào sau quét | “Bấm “Mật Mật giải thích” ở từng mục” | **Nút không tồn tại** (nút thật: “Hỏi Mật Mật về mục này”) | “Chọn từng mục bên dưới để xem giải thích, hoặc bấm “Hỏi Mật Mật về mục này”” |
| Báo cáo, chế độ Dễ hiểu | 3 việc nên làm trước viết dạng câu hỏi (“Mã nguồn gốc của website có tải về được không?”) | Người mới không biết “có” là tốt hay xấu | Thêm dòng “Kết quả: Source map JavaScript có thể tải công khai” |
| Báo cáo, chế độ Dễ hiểu | Khối prompt AI thô (“Bạn là kỹ sư bảo mật…”) hiện giữa phần tóm tắt | Chữ kỹ thuật chặn giữa màn hình chính của người không dùng AI | Gấp lại sau “Xem nội dung prompt (dành cho người dùng Cursor / Claude Code / ChatGPT)” |
| Từ điển thuật ngữ | Thiếu: header, DKIM, Referrer-Policy, Permissions-Policy, COOP/COEP, Report-Only, CDN, DNS; SameSite mô tả quá mạnh | Người dùng gặp thuật ngữ không có giải thích | Bổ sung 10 mục; DKIM ghi rõ **VibeSec chưa kiểm tra** (cần selector) |

### 5.2 Đánh giá từng thuật ngữ (mô phỏng chuyên gia)

| Thuật ngữ | Giải thích tiếng Việt | Ví dụ đời thường | Vì sao cần quan tâm | Phân biệt rủi ro thật / best practice | Hướng xử lý |
|---|---|---|---|---|---|
| CSP | Có | “danh sách khách mời” | Có | **Có** (“thiếu CSP không có nghĩa là đang bị chèn mã”) | Có, kèm Report-Only trước |
| HSTS | Có | “chỉ nói chuyện qua kết nối an toàn” | Có | Có (lần truy cập đầu, wifi công cộng) | Có; nay xử lý đúng đuôi `.dev/.app` |
| CORS | Có | “ai được đọc sổ sách của bạn” | Có | **Có** (`*` công khai ≠ phản chiếu + cookie) | Có |
| XSS | Có | — | Có | Có (CSP chỉ là lớp thứ hai) | Qua CSP |
| CSRF | Có (từ điển) | — | Có | — | Qua SameSite |
| TLS | Có (đã viết lại) | “ổ khoá” | Có | Có (TLS 1.0/1.1 vs 1.2/1.3) | Có |
| Security headers | **Mới bổ sung** | “biển báo an toàn” | Có | Có | Nêu nơi sửa (hosting/CDN, Next.js) |
| Clickjacking | Có | “khung vô hình, bấm nhầm nút” | Có | Có (mức thấp nếu trang không có thao tác nhạy cảm) | Có |
| SameSite / HttpOnly / Secure | Có (SameSite đã chỉnh lại) | “tem chống giả trên vé gửi xe” | Có | Có (đoán “cookie phiên” từ tên được ghi rõ) | Có, theo từng cờ thiếu |
| SPF / DKIM / DMARC | Có / **Mới** / Có | “chữ ký thư của công ty” | Có | Có (“không biết tên miền có gửi thư không”) | Có; DKIM: chưa kiểm tra |
| Referrer-Policy | **Mới bổ sung** | “bạn đến từ đâu” | Có | Có (mặc định trình duyệt hiện đại đã an toàn) | Có |
| Permissions-Policy | **Mới bổ sung** | camera/micro/vị trí | Có | Có (mức thông tin) | Có |

Còn tồn tại: nhật ký “màn hình trực tiếp” khi đang quét vẫn là lệnh kỹ thuật (`dig A …`, `scheme=https`); cột bên trái đã là tiếng Việt nên người mới vẫn theo dõi được. Giữ nguyên vì đó là phần trang trí cho người kỹ thuật.

## 6. Hướng dẫn sửa: có làm theo được không?

Đánh giá trên 63 luật (mỗi luật có mẫu giải thích riêng, khoá bởi `explain-quality.test.ts`):

| Tiêu chí | Tình trạng |
|---|---|
| 1. Vấn đề là gì | 63/63 có “Chúng tôi thấy” nêu giá trị thật của website |
| 2. Vì sao cần quan tâm | 63/63; kèm “Trong 1 ngày / Xấu nhất / Ai khai thác được” cho mục chưa đạt |
| 3. Mức ưu tiên | “Sửa ngay hôm nay / trong tuần / khi rảnh” + mức chắc chắn (đã xác nhận / tiềm năng / chưa đủ dữ liệu) |
| 4. Sửa ở đâu | Mỗi bước có vai trò: Lập trình viên / Quản trị hosting–CDN / Người quản lý tên miền / Chủ website. Đoạn cấu hình theo nền tảng phát hiện được (Vercel, Netlify, Cloudflare, Next.js, Nginx…) |
| 5. Sửa thế nào | Các bước + đoạn cấu hình chép được |
| 6. Cần cẩn thận gì | Có ở CSP (Report-Only trước), HSTS preload (khó gỡ), COOP/COEP (làm hỏng đăng nhập bằng cửa sổ bật lên), đổi tên cookie (đăng xuất mọi người) |
| 7. Kiểm tra lại | Lệnh chỉ-đọc “Tự kiểm tra lại” với đúng tên miền; nút “Quét lại sau khi sửa” ở báo cáo đầy đủ |

Khoảng trống còn lại giữa **phát hiện** và **sửa được**:
- Người **không dùng AI viết code và không có lập trình viên**: phần lớn bước sửa header cần vào hosting/CDN. Hướng dẫn có, nhưng chưa có ảnh/video từng bước cho Vercel/Cloudflare.
- Đoạn CSP mẫu là **ví dụ cần điều chỉnh** (được ghi rõ, và có lời khuyên chạy Report-Only trước) — không thể có một CSP đúng cho mọi website.

## 7. Trải nghiệm & tải nhận thức

Đã đo trong trình duyệt (desktop, 768px, 390px, 375px):
- **Tràn ngang ở 375/390px**: sau khi đổi nhãn trạng thái dài hơn, cột danh sách phát hiện trong quét nhanh rộng 459px trong khung 333px (chữ bị cắt). **Đã sửa** (`grid-cols-[minmax(0,1fr)]`); đo lại: 0 phần tử tràn.
- **Progressive disclosure**: mặc định chỉ hiện “Cần xử lý”; “Tham khảo”, “Đạt”, “Tất cả” là bộ lọc riêng. Chi tiết kỹ thuật (bằng chứng, lệnh tái hiện, OWASP) nằm dưới phần giải thích; ở báo cáo đầy đủ chế độ Dễ hiểu, phần kỹ thuật gấp sau “Xem chi tiết kỹ thuật (không bắt buộc)”.
- **Có thể chép** từng đoạn cấu hình, lệnh kiểm tra, prompt AI; xuất JSON/Markdown.
- **Thông báo lỗi** nay luôn nói bước tiếp theo (không kết nối được, HTTPS không mở được, bị tường lửa chặn, hết lượt quét).
- **Còn tồn tại (P2)**: trên điện thoại, danh sách và chi tiết nằm trong một khung cao cố định với hai vùng cuộn lồng nhau; nên chuyển sang danh sách gập/mở khi < 768px. 3 nút “Hỏi dòng này / Copy prompt / Hỏi Mật Mật” khi bị gấp trong `<details>` vẫn có tên đọc được (đã kiểm tra), không có ảnh thiếu `alt`.

## 8. Hành trình người dùng (mô phỏng chuyên gia, **không phải người dùng thật**)

| Hành trình | Thao tác đến khi biết việc cần làm | Điểm bối rối (trước) | Sau sửa |
|---|---|---|---|
| A — Vibe coder vừa deploy lên `*.vercel.app` | 3 (dán URL → Enter → đọc “Nên làm trước”) | Bị yêu cầu thêm SPF/DMARC/CAA cho tên miền của Vercel → **ngõ cụt** (không có quyền) | Mục DNS là “Tham khảo: không áp dụng”, giải thích khi nào cần |
| B — Chủ shop không biết header | 4 | “Lỗi” ở mọi chỗ, tên nhóm `CSP`, `CORS`; câu hỏi “…có tải về được không?” không rõ tốt/xấu | Nhãn “Cần sửa / Nên cải thiện”, tên nhóm tiếng Việt, dòng “Kết quả: …”, vai trò “Quản trị hosting / CDN” chỉ ra nên chuyển cho ai |
| C — Junior dev nhận lỗi CSP | 5 (mở mục → đọc → chép cấu hình Next.js → chép lệnh kiểm tra) | CSP chiếm 2/3 việc ưu tiên, tưởng là hai lỗi | Một mục + ghi chú “Cùng nguyên nhân…”; hướng dẫn `proxy.ts` (Next 16) |
| D — Freelancer giải thích cho khách | 3 (Chép Markdown) | Bản Markdown không nói phạm vi điểm | Bản Markdown có câu phạm vi và mục “Tham khảo / chưa kiểm tra được” |
| E — Dev có kinh nghiệm | 2 (tab Kỹ thuật, bằng chứng từng dòng) | Không biết vì sao trang 403 vẫn bị chấm | Từ chối chấm với lý do; tab “Điểm & phạm vi” liệt kê từng khoản trừ |

Thời gian không được đo vì không có người dùng thật; xem `docs/user-testing/README.md` để đo thật với 5 người.

## 9. Chấm chất lượng nội dung (mô phỏng chuyên gia, 1–5)

Trọng số: Dễ hiểu 30% · Tiếng Việt tự nhiên 20% · Chính xác 20% · Làm theo được 20% · Trực quan 10%.

| Màn hình / nhóm | Dễ hiểu | Tiếng Việt | Chính xác | Làm theo được | Trực quan | Tổng (trước → sau) |
|---|---|---|---|---|---|---|
| Trang chủ | 2 → 4 | 2 → 4 | 3 → 4 | 3 → 3 | 4 → 4 | 2,6 → **3,8** |
| Quét nhanh — kết quả | 3 → 4 | 3 → 4 | 3 → 4 | 4 → 4 | 3 → 4 | 3,2 → **4,0** |
| Báo cáo đầy đủ — Dễ hiểu | 3 → 4 | 4 → 4 | 3 → 4 | 4 → 4 | 3 → 4 | 3,4 → **4,0** |
| Luật TLS/HSTS/chuyển hướng | 4 | 4 | 3 → 5 | 4 | 4 | 3,8 → **4,2** |
| Luật header/CSP | 4 | 4 | 3 → 5 | 4 | 4 | 3,8 → **4,2** |
| Luật cookie/cache | 4 | 4 | 3 → 4 | 4 | 4 | 3,8 → **4,0** |
| Luật DNS/email | 3 → 4 | 4 | 2 → 4 | 2 → 4 | 4 | 2,8 → **4,0** |
| Luật lộ thông tin/khoá bí mật | 4 | 4 | 4 → 5 | 4 | 4 | 4,0 → **4,2** |

## 10. Kiểm thử

| Kiểm thử | Kết quả |
|---|---|
| `npm run typecheck` (app + Worker) | **PASS** |
| `npx vitest run` | **PASS** — 47 tệp, 1116 test (trước: 1073) |
| Test mới | `audit-regressions.test.ts` (21), `platform-domain.test.ts` (1), bổ sung `explain-quality.test.ts` (nền tảng, tên miền DNS), `quick-scan.test.ts` (không kết nối được, nhãn tiếng Việt), `rules.test.ts`, `advanced.test.ts` |
| `npm run build:cf` + `wrangler deploy --dry-run` | **PASS** |
| E2E trình duyệt: trang chủ → quét thử → lọc → giải thích → giải pháp → chép | **PASS** (desktop, 375px) |
| Responsive 375/390/768px: tràn ngang | **PASS** sau sửa (trước sửa: FAIL ở 375px với nhãn mới) |
| Truy cập: nút có tên, ảnh có `alt` | **PASS** (kiểm tra DOM tự động; chưa chạy trình đọc màn hình thật) |
| Kiểm thử với người dùng thật | **BLOCKED** — không có người tham gia; quy trình có sẵn ở `docs/user-testing/` |
| Quét website bên thứ ba có cấu hình CDN/tường lửa thật | **BLOCKED** có chủ đích — chỉ quét website của chính VibeSec; tình huống CDN/403 được kiểm bằng fixture |

## 11. Giới hạn còn lại

1. Không có dữ liệu người dùng thật: mọi điểm ở §8–§9 là mô phỏng chuyên gia.
2. Quét thụ động không thấy phân quyền, logic nghiệp vụ, database, mã phía máy chủ: điểm cao **không** phải chứng nhận an toàn (đã ghi ở mọi nơi hiển thị điểm).
3. Các thay đổi chấm điểm (gộp nguyên nhân gốc, trần theo phạm vi, mức độ A7/A8/A9) làm điểm của một số website thay đổi sau khi deploy; cache cũ tự hết hiệu lực nhờ `ENGINE_VERSION = 10`.
4. Danh sách §3.3 chưa sửa.


---

# Đợt 2 (2026-10-18): độ chính xác, phạm vi quét, OWASP 2025, độ tin cậy

Nhánh `improve/accuracy-coverage-ux`. Mọi mục dưới đây có test chạy được; “giả lập” nghĩa là phản hồi HTTP/DNS được dựng trong test, **không phải** quét website thật.

## 12.1 Điểm bảo mật tách khỏi phạm vi quét (P0)

| Trước | Sau |
|---|---|
| Quét nhanh tối đa 90 → **hạng A** dù chỉ xem trang chủ | Tối đa **89 (hạng B)**. Hạng A chỉ khi **mọi nhóm kiểm tra áp dụng được** đều đã được kiểm tra |
| Một nhóm không có dữ liệu (HTTPS lỗi, DNS lỗi) → các luật im lặng, điểm vẫn có thể 96/A | Trần 89 và hiện “Phạm vi quét: đã kiểm tra X/Y nhóm · chưa đầy đủ nên không xếp hạng A”, bấm để xem từng nhóm |
| Ba trạng thái (đạt / lỗi / thông tin), “chưa kiểm tra được” và “không áp dụng” lẫn vào nhau | Bốn loại kết quả tách biệt: **ĐẠT · CHƯA ĐẠT · CHƯA KIỂM TRA ĐƯỢC · KHÔNG ÁP DỤNG** (cộng “tham khảo”) |

- 8 nhóm: HTTPS và chuyển hướng · chứng chỉ/TLS · header/CSP · cookie · CORS · nội dung trang · DNS/email · tệp công khai. “Không áp dụng” không tính vào mẫu số. Ở quét nhanh, chứng chỉ chi tiết là “chỉ có ở quét đầy đủ”.
- **Không áp dụng** được lưu là `status: "info"` với khoá fingerprint bắt đầu bằng `na-` (vd. `config.dns-email-security|na-platform`, `cookies.flags|na-no-cookies`). Cách này **không cần đổi lược đồ CSDL**: bảng `findings` có ràng buộc `CHECK (status IN ('fail','pass','info','unknown'))`, và một migration chạy trên D1 production có thể làm hỏng việc lưu lượt quét nếu code mới deploy trước. Phạm vi được tính lại từ chính các phát hiện, nên báo cáo đã lưu cũng hiển thị được.
- “Không có cookie nào” trước đây là **ĐẠT**, nay là **KHÔNG ÁP DỤNG** (VibeSec không đăng nhập nên không thấy cookie sau đăng nhập).
- Lộ trình sửa (`buildRoadmap`) coi mục đã xử lý là ĐẠT thay vì xoá, để không làm nhóm đó trông như “chưa kiểm tra được”.

Kiểm chứng thật trên chính website VibeSec (quét nhanh, đường mạng thật, bản dev của nhánh này): **89/B**, “đã kiểm tra 5/6 nhóm” — HTTPS, header, CORS, nội dung, tệp: đã kiểm tra · chứng chỉ: chỉ có ở quét đầy đủ · cookie, DNS: không áp dụng (không đặt cookie; tên miền con của `workers.dev`).

## 12.2 Độ chính xác luật

| ID | Vấn đề | Sửa | Test |
|---|---|---|---|
| A12 | SPF: `~all` bị luật cơ bản nói “đạt, chặt chẽ” còn luật sâu báo yếu; thiếu `all` không bị báo; `+all` mức Trung bình ở luật này, Cao ở luật kia | Một bộ phân tích dùng chung (`rules/spf.ts`): `-all`/`~all` đạt ở **cả hai**; `?all` và **thiếu `all`** (mặc định trung lập, RFC 7208) bị báo ở cả hai; `redirect=` không suy đoán; cùng mức độ | 6 cấu hình × 2 luật |
| A13 | Trang 404 thử nghiệm trả 3xx vẫn bị so header | Chỉ so khi mã ≥ 400 | — |
| A14 | Không có cookie → “Đạt” | → “Không áp dụng” | benchmark #15 |
| SEV | TRACE mức Trung bình (trình duyệt hiện đại chặn TRACE từ fetch/XHR) | Thấp | `hardening.test.ts` |
| SEV | Hạn chứng chỉ dài: luật cơ bản Thấp, luật sâu Trung bình | Thấp ở cả hai | — |
| CSP trùng | Đã gộp ở đợt 1 | Thêm kiểm chứng end-to-end: 2 mục hiển thị, chỉ 1 mục trừ điểm | benchmark #13 |

## 12.3 Benchmark 16 cấu hình theo nền tảng (giả lập toàn bộ luồng quét nhanh)

`src/lib/scanner/__tests__/platform-scenarios.test.ts` — mỗi cấu hình có đáp án viết tay (phải báo / không được báo):

| # | Cấu hình | Kết quả kiểm chứng |
|---|---|---|
| 1 | Cloudflare proxy, cookie `__cf_bm`, cache HIT, `server: cloudflare` | Không báo rò rỉ phiên, không báo lộ phiên bản; không hạng A (quét nhanh) |
| 2 | Cloudflare “Just a moment…” 403 | Từ chối chấm điểm |
| 3 | `*.vercel.app` mặc định, không header bảo mật | DNS/email: không áp dụng; thiếu CSP/chống nhúng vẫn bị báo; không đòi HSTS preload |
| 4 | `*.netlify.app` với `_headers` chặt | Không lỗi nào quy cho chủ website |
| 5 | Tên miền riêng, SPF `~all`, DMARC `p=none` | SPF đạt; DMARC `p=none` bị báo |
| 6 | DNS-over-HTTPS lỗi hoàn toàn | Không bịa lỗi DNS; nhóm DNS “chưa kiểm tra được”; có ghi chú phạm vi |
| 7 | Chỉ HTTP | Từ chối chấm điểm, hướng dẫn bật HTTPS |
| 8 | Không kết nối được | “Chưa quét được”, không 0/F |
| 9–10 | `.dev` vs `.com` không chuyển hướng HTTP | `.dev`: tham khảo · `.com`: lỗi thật |
| 11 | Header lặp do hai lớp proxy | Không báo sai |
| 12–13 | CSP strict (nonce + strict-dynamic) vs `'unsafe-inline'` | Đạt vs báo (một khoản trừ) |
| 14–15 | Cookie phiên thiếu cờ vs không có cookie | Báo vs không áp dụng |
| 16 | Website chuẩn trên tên miền riêng | 0 lỗi, 89/B |

**Không làm:** quét website thật của Cloudflare/Vercel/Netlify hay của người khác (không có quyền). Website thật duy nhất được quét là VibeSec (§12.1).

## 12.4 Độ tin cậy

| Hạng mục | Kết quả |
|---|---|
| **Quét đồng thời (lỗi thật, đã sửa)** | Quét nhanh “đếm rồi mới ghi” → **8 yêu cầu song song tới cùng một website đều được quét dù hạn mức 3/giờ** (đã tái hiện bằng test). Nay giữ chỗ trước rồi đếm theo thứ tự id: đúng 3 lượt chạy, 5 lượt nhận 429, chỗ giữ của lượt bị từ chối được xoá. Cùng một IP gửi 5 yêu cầu song song với hạn mức 2 → đúng 2. Quét đầy đủ đã dùng một câu `INSERT … SELECT … WHERE` nguyên tử nên không bị lỗi này. |
| SSRF | 227 test hiện có (IP nội bộ, metadata, DNS rebinding, chuyển hướng tới địa chỉ nội bộ, cổng lạ) vẫn đạt |
| Cache | Kết quả “không kết nối được / bị chặn / không có HTTPS” không được lưu (test); `ENGINE_VERSION` 10 → 11 để kết quả chấm theo cách cũ không bị dùng lại |
| Timeout | DoH 4 giây/truy vấn; ngân sách quét nhanh 14 request / 2 MB / 12 giây (test hiện có) |

## 12.5 Lỗi Workers Builds trên nhánh PR (điều tra, chưa sửa — cần chủ tài khoản)

Không đọc được log trên Cloudflare (công cụ Cloudflare cần OAuth). Bằng chứng từ GitHub Checks và tài liệu Cloudflare:

- **100% build trên nhánh không phải `main` thất bại, mỗi lần dưới 100 giây** (build trên `main` mất 3–4,5 phút). Tài liệu Cloudflare ghi lệnh mặc định của nhánh không phải production là `wrangler versions upload`, lệnh này **không** triển khai container, và Worker có Durable Objects/Containers **không** có URL xem trước. **Giả thuyết mạnh nhất**: bước xem trước (preview) thất bại phía máy chủ với Worker có Containers. `wrangler versions upload --dry-run` chạy cục bộ thì qua, nên chưa xác nhận.
- Hai lần thất bại trên `main` (`f718cf0`, `a1b6fa4`) chạy đủ thời gian và code của `a1b6fa4` **vẫn được phục vụ**. Điều này khớp với tài liệu: Worker được kích hoạt trước bước image/rollout của container, nên lỗi ở bước sau vẫn đánh dấu build thất bại. Bước cụ thể bị lỗi chưa xác nhận.
- **Việc chủ tài khoản nên làm** (không áp dụng tự động):
  1. Mở log build PR (vd. `4800dc63…`) và `79927e71…` để xác nhận.
  2. Tắt “Enable Preview Builds” (Settings → Build → Branch control), vì CI của GitHub đã chạy `wrangler deploy --dry-run`. Hoặc đổi lệnh preview thành `npx wrangler deploy --dry-run --containers-rollout=none`. **Không** dùng `wrangler deploy` cho nhánh: lệnh này cuộn container production.

## 12.6 OWASP Top 10:2025 (đã kiểm chứng trước khi đổi)

- **Nguồn chính thức:** README của repo `OWASP/Top10` ghi “OWASP Top 10 2025 - RELEASED … (Final)” và “2021 - SUPERSEDED” (tôi tự kiểm lại). Tên 10 hạng mục và danh sách CWE của từng hạng mục lấy từ `2025/docs/en` trong cùng repo.
- **Đã đổi:**
  - `OWASP_MAP`: 54 luật có ánh xạ 2025; 9 luật cố ý không ánh xạ vì không thuộc rủi ro nào (hiệu năng, thông tin tham khảo, quyền riêng tư). Test khoá cả danh sách này.
  - Bảng độ phủ: 9/10 hạng mục, vì SSRF đã gộp vào A01 và A10 mới (“xử lý sai tình huống bất thường”) thấy được một phần qua trang lỗi.
  - Liên kết từng hạng mục và nhãn trang chủ đổi theo 2025.
- **Ánh xạ sai đã sửa:**
  - `adv.web-storage-secrets` sang A01 (CWE-922).
  - `exposure.secrets` sang A07 (CWE-798).
  - `config.suspicious-redirects` sang A04. Luật này kiểm hạ cấp HTTPS→HTTP, không phải open redirect, nên CWE-601 / ASVS 5.1.5 / WSTG-CLNT-04 đổi thành CWE-319 / 9.1.1 / WSTG-CRYP-03.
  - `browser.form-targets` bỏ A08.
- **ASVS:** bản 5.0.0 đã phát hành (GitHub release 2025-05-30) nhưng **chưa kiểm chứng mã yêu cầu 5.0** tương ứng, nên **giữ 4.0.3** có ghi rõ phiên bản. Việc chuyển sang 5.0 để thành một việc riêng.
- **Chưa kiểm chứng:**
  - Ngày phát hành chính thức của Top 10:2025.
  - Tên tiếng Việt của các hạng mục (OWASP chưa có bản tiếng Việt; tên trong VibeSec là bản dịch của chúng tôi).

## 12.7 Giao diện

- **Điện thoại (sửa lỗi P2 của đợt 1):**
  - Danh sách phát hiện và phần chi tiết không còn nằm trong khung cao cố định với hai vùng cuộn lồng nhau. Trang cuộn tự nhiên, danh sách rồi chi tiết nối tiếp nhau.
  - Chạm một mục là cuộn tới phần chi tiết; nút “↑ Về danh sách mục” để quay lại.
  - Kiểm chứng ở 375px: 0 vùng cuộn lồng nhau, 0 phần tử tràn. Đợt này phát hiện và sửa thêm một lỗi cột chi tiết rộng 413px trong khung 391px.
  - Desktop giữ bố cục chia cột như cũ.
- **Đường đi chính cho người mới:** “Nên làm trước” có câu hướng dẫn và bấm vào là cuộn tới giải thích. Nút “Copy prompt cho AI” chuyển thành nút phụ.

## 12.8 Kiểm thử đợt 2

| Kiểm thử | Kết quả |
|---|---|
| `npm run typecheck` | PASS |
| `vitest` | **PASS — 48 tệp, 1147 test** (đợt 1: 1116) |
| `build:cf` + `wrangler deploy --dry-run` | PASS |
| E2E trình duyệt: quét thử thật website VibeSec → phạm vi → lọc → chi tiết; desktop + 375px | PASS |
| Quét website thật của nền tảng/người khác | Không làm (không có quyền) — thay bằng 16 cấu hình giả lập |
| Kiểm thử người dùng thật | Chưa làm |
