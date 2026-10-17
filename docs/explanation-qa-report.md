# Báo cáo Security Explanation Quality Assurance

## 1. Coverage giải thích theo 63 luật

| Trước | Sau |
|---|---|
| 17/63 luật có mẫu riêng (một số chỉ có 1–2 biến thể); 46/63 dùng fallback dựng từ `summary`/`explanation` chung | **63/63** luật có mẫu riêng; được khoá bằng test `explain-quality.test.ts` (không còn fallback, kể cả từng biến thể) |

Mỗi mẫu có đủ chuỗi **bằng chứng → nguyên nhân → hệ quả → cách sửa → cách xác minh**, cộng hai trường mới:
`certainty` (đã xác nhận / rủi ro tiềm năng / chưa đủ dữ liệu) và `caveat` (giới hạn của bằng chứng). Giao diện hiển thị mục “Mức chắc chắn” và “Tự kiểm tra lại: <lệnh chỉ đọc>”.

Biến thể được viết riêng (không chỉ đổi từ trong template chung):

- **CSP**: thiếu hẳn · chỉ Report-Only · `'unsafe-inline'` · `'unsafe-eval'` · mọi host/`https:` · `data:`/`blob:` · host công cộng · thiếu script-src.
- **CORS**: phản chiếu origin (có/không credentials) · `null` · `*` công khai · `*` + credentials (trình duyệt tự chặn → không phải lỗ hổng).
- **Cookie**: lời giải thích theo từng cờ thiếu (Secure / HttpOnly / SameSite / SameSite=None thiếu Secure / tiền tố / thời hạn dài), phân biệt “giống cookie phiên” (đoán từ tên) với cookie thường.
- **HSTS / TLS**: HSTS thiếu · preload không hợp lệ/chưa sẵn sàng · chứng chỉ ≤14 ngày vs ≤30 ngày · khoá yếu / hạn quá dài / wildcard · TLS 1.0/1.1 · cipher yếu vs thiếu forward secrecy · không có HTTPS vs chứng chỉ không tin cậy vs “không kết nối ổn định” (inconclusive) · www/non-www.
- **DNS/email**: DMARC thiếu/`p=none`/`pct<100` · SPF thiếu/`+all`/`?all`/vượt 10 lookup/nhiều bản ghi · CAA · DNSSEC · MTA-STS · một NS.
- **Authentication**: form mật khẩu gửi tới `http://` / dùng GET / nằm trên trang HTTP · bề mặt đăng nhập (info, không phải lỗi) · form gửi sang website khác.
- **Exposure**: secrets · public-config · source map · robots/sitemap · thư viện cũ · subdomain takeover · tham chiếu nội bộ · mọi luật `adv.*`.

Phân loại 63 luật sau audit (số ngoặc: luật):

| Loại | Luật |
|---|---|
| Đã xác nhận được (quan sát trực tiếp) | HSTS, TLS version/expiry/strength, redirect HTTP→HTTPS, header thiếu/sai, cookie flags, SPF/DMARC/CAA/DNSSEC, source map, security.txt, mixed content |
| Rủi ro tiềm năng (tuỳ ngữ cảnh/suy luận) | `exposure.secrets`, `exposure.outdated-libraries`, `exposure.subdomain-takeover`, `adv.dom-xss-flow`, `adv.postmessage`, `adv.web-storage-secrets`, `adv.supply-chain`, `adv.graphql-surface`, `adv.endpoint-map`, `config.auth-surface`, `config.http-methods` (write), `cookies.prefix`, CORS `*`, `privacy.*` |
| Chưa thể kết luận | `tls.https-available` (unknown), chuyển hướng bị chặn (`blocked`), mọi luật khi thiếu dữ liệu TLS (không phát sinh kết luận) |

## 2. Lỗi kỹ thuật đã sửa

1. **False positive CSP “strict CSP”** (`adv.csp-analysis`): `'nonce-…' 'strict-dynamic' 'unsafe-inline' https:` — mẫu khuyến nghị của Google — bị báo mức *medium*. Nay bỏ qua nguồn rộng khi có `strict-dynamic`/nonce (khớp với `headers.csp`).
2. **False positive cookie CSRF** (`cookies.prefix`): `XSRF-TOKEN` (cố ý cho JS đọc) bị coi là cookie phiên thiếu `__Host-`. Nay loại cookie csrf/xsrf.
3. **Rò rỉ qua nhận xét tự do**: nhận xét được lưu nguyên văn. Nay tự động ẩn URL, email, IPv4/IPv6, tên miền, token/khoá quen thuộc, chuỗi dài giống token, số điện thoại **trước khi lưu**; bỏ ký tự điều khiển/đảo chiều chữ (Trojan-source); giao diện nhắc người dùng không ghi dữ liệu nhạy cảm.
4. **Kết luận từ mẫu nhỏ ở `/admin/giai-thich`**: trước đây 3 phiếu & ≥50% đã tô đỏ. Nay `n < 10` chỉ hiện “mẫu nhỏ (n=…)”; “ưu tiên viết lại” chỉ khi cận dưới Wilson 95% của tỉ lệ “Chưa” ≥ 30%.
5. **Giới hạn kích thước** body của `/api/explain-feedback` (4 KB, trả 413).
6. Mẫu CSP cũ coi “chỉ có Report-Only” như “không có CSP”; nay phân biệt đúng.

## 3. Tính toàn vẹn bình chọn / spam / XSS / quyền admin

| Hạng mục | Kết quả |
|---|---|
| Một người một phiếu mỗi (luật, biến thể) | Đúng: `UNIQUE(voter_hash, rule_id, variant)` + upsert; test xác nhận đổi phiếu không nhân đôi |
| Chống spam | 60 phiếu/giờ/người (băm HMAC của IP hoặc user); `sameOrigin`; `ruleId` phải là một trong 63 luật; `variant` lọc `^[a-z0-9-]{1,32}$` |
| Rò rỉ | Không lưu tên miền/URL/IP thô; comment chỉ lưu khi “Chưa”, đã ẩn dữ liệu nhận dạng |
| XSS | Không có `dangerouslySetInnerHTML` trong `src/components` và `src/app` (test chặn); comment hiển thị bằng text React (escape) |
| Quyền admin | `/admin/giai-thich` gọi `getAdmin()` (email trong ADMIN_EMAILS **và** đã liên kết Google); kiểm thử E2E: người ẩn danh nhận **404** |
| Rủi ro còn lại (chưa xử lý) | (a) Kẻ dùng nhiều IP vẫn nhồi được phiếu (không có CAPTCHA/Turnstile — nằm ngoài phạm vi); (b) đếm giới hạn rồi chèn không nguyên tử (có thể vượt vài phiếu khi song song); (c) nếu hạ tầng không cung cấp IP, mọi người ẩn danh dùng chung một xô “unknown” — không xảy ra sau Cloudflare; (d) bộ lọc ẩn dữ liệu là heuristic, có thể sót (vd. tên riêng, địa chỉ nhà) |

## 4. Các trường hợp chưa đủ bằng chứng (ghi rõ trong giải thích)

- Mọi phát hiện chỉ dựa trên cấu hình **không** được khẳng định là đã/đang bị khai thác; `caveat` nói rõ điều đó.
- CORS: chỉ thử trang chủ, chưa biết các API riêng tư có cùng quy tắc không.
- `exposure.secrets`, `exposure.public-config`: khớp mẫu và che giá trị; nhiều khoá (Stripe publishable, Firebase API key) vốn công khai.
- `exposure.outdated-libraries`: phiên bản đoán từ tên tệp; không thử khai thác.
- `adv.dom-xss-flow`, `adv.postmessage`: phân tích tĩnh, độ tin cậy thấp.
- `subdomain-takeover`: thấy CNAME trỏ dịch vụ trống, chưa đăng ký thử tài nguyên đó.
- Email (SPF/DMARC): không biết tên miền có thực sự gửi thư.
- Giữ nguyên: ACAO `*` không kèm cookie vẫn là “fail” mức thấp, độ tin cậy thấp (có thể là chủ ý cho tài nguyên công khai); chuyển thành “info” sẽ đổi điểm số và benchmark nên **không** làm trong đợt này — giải thích đã ghi nhãn “tiềm năng”.

## 5. User testing

Quy trình 4–5 người, 10 phát hiện, thang chấm Q1–Q5, tiêu chí đạt và cách kết hợp với dashboard: xem [user-testing-explanations.md](./user-testing-explanations.md). **Chưa chạy buổi test nào** — cần người thật.

## 6. Kiểm thử

| Kiểm thử | Kết quả |
|---|---|
| `vitest run` | **38 file / 922 test đạt** (trước đợt này 908 sau khi thêm phần luật; thêm: 135 test chất lượng giải thích gồm 63/63 luật × biến thể, kiểm “không khẳng định quá mức”, 6 kịch bản false positive, redaction, ngưỡng mẫu, no-raw-html) |
| `npm run typecheck` | Còn 2 lỗi **có sẵn từ trước, không do thay đổi này** (`src/lib/project/github.ts:65`, `src/lib/ssrf/fetch.ts:259`; tái hiện trên cây sạch bằng `git stash`) |
| Browser E2E (dev server, `/demo`) | Giải thích hiển thị “Mức chắc chắn” và “Tự kiểm tra lại” với tên miền thật; không lỗi console; không tràn ngang ở viewport mobile 375px; POST bình chọn trả 201; `/admin/giai-thich` ẩn danh → 404 |
| Chưa kiểm | Giao diện admin khi đăng nhập quản trị (không có tài khoản trong phiên); ảnh chụp cuộn tới phần giải thích bị hạn chế bởi hiệu ứng reveal của trang nên xác minh bằng DOM, không bằng ảnh |

## 7. Production

**Chưa xác minh.** Chưa push và công cụ Cloudflare Workers Builds trong phiên này chưa được cấp quyền, nên chưa thể xác nhận commit nào đang chạy ở production. Xem mục tiếp theo của phiên làm việc.
