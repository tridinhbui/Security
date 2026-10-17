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

## 7. CI và production (cập nhật 2026-10-17)

**Hai lỗi typecheck từng làm CI đỏ (đã sửa ở commit `e02e4cb`, tách riêng khỏi phần giải thích):**

| Lỗi | Nguyên nhân gốc | Sửa |
|---|---|---|
| `src/lib/project/github.ts:65` — `ignoreBOM` thiếu | `@cloudflare/workers-types` khai báo `TextDecoderConstructorOptions` với **cả hai** trường `fatal` và `ignoreBOM` là bắt buộc (lib.dom/@types/node để tuỳ chọn). Lỗi chỉ xuất hiện ở chương trình `worker/tsconfig.json` | Truyền đủ `{ fatal: false, ignoreBOM: false }` — đúng giá trị mặc định theo chuẩn nên runtime không đổi |
| `src/lib/ssrf/fetch.ts:259` — `toString` “Expected 0 arguments” | `worker/tsconfig.json` có `types: ["@cloudflare/workers-types"]` và kéo `fetch.ts` (mã Node) vào qua chuỗi import `jobs/* → scanner/tls-inspect.ts → ssrf/fetch.ts`. Trong chương trình đó, kiểu `Buffer` mất overload `toString(encoding)` (thử `types: ["node"]` riêng thì hết lỗi; thêm `node` cạnh workers-types vẫn lỗi; import `Buffer` từ `node:buffer` vẫn lỗi). Chưa truy đến dòng khai báo xung đột cụ thể trong workers-types | Thay `res.body.toString("utf8")` bằng `decodeUtf8()` dùng `TextDecoder("utf-8", { fatal:false, ignoreBOM:true })` — giữ BOM và thay byte lỗi bằng U+FFFD như Buffer. Không đụng tới SSRF validation, DNS pinning, redirect handling, GitHub fetch |

Không dùng `any`, `@ts-ignore`, ép kiểu hay nới cấu hình typecheck. Tính tương đương hành vi được khoá bằng `src/lib/ssrf/__tests__/fetch-decode.test.ts` (so với `Buffer#toString`: văn bản hợp lệ, BOM, byte lỗi/overlong/surrogate/cắt giữa chừng, 3000 mẫu ngẫu nhiên, subarray). Hạn chế: sự tương đương kiểm bằng thực nghiệm trên Node cục bộ, không phải chứng minh hình thức.

**Kiểm thử cục bộ:** `npm run typecheck` sạch (cả hai chương trình); vitest 39 file / 927 test đạt; `build:cf` và `wrangler deploy --dry-run` thành công.

**GitHub Actions / Workers Builds (kiểm lại 2026-10-17):**

| Commit | Job `test` | Workers Builds |
|---|---|---|
| `1e73d61` | thất bại (2 lỗi typecheck có sẵn) | thành công |
| `e02e4cb` | **thành công** | thành công |
| `f718cf0` (chỉ đổi tài liệu) | **thành công** | **THẤT BẠI** — chưa rõ nguyên nhân |

Nhật ký build nằm ở Cloudflare dashboard (Build ID `138a523c-0949-40ed-b591-630214673ffd`); GitHub không có chi tiết và công cụ Cloudflare trong phiên chưa được cấp quyền, nên **chưa chẩn đoán được**. Commit chỉ đổi file `.md` nên khó là lỗi mã; có thể do build bị chồng lên build `e02e4cb` đang chạy vài phút trước hoặc sự cố nền tảng, nhưng đây là suy đoán chưa kiểm chứng. Tôi không chạy lại build vì đó là deploy.

**Production — mức xác minh:**
- Build thành công ≠ đang phục vụ. Build `e02e4cb` thành công (Version ID `89d80d8d-f991-41cc-89ac-fe53e56db070`) nhưng chưa có bằng chứng đây là phiên bản đang nhận traffic; build kế tiếp thất bại nên nhiều khả năng Worker vẫn ở `e02e4cb`, **chưa xác minh**.
- Kiểm tra gián tiếp trước đó: `/demo` trên production chứa chuỗi chỉ có từ `1e73d61` → production chạy *ít nhất* `1e73d61`.
- **Đã thêm `/api/version`** (commit riêng, **chưa deploy**): trả đúng 4 trường `commit` (nhúng lúc build từ `WORKERS_CI_COMMIT_SHA`/`GITHUB_SHA`, chỉ nhận SHA hex), `builtAt`, `workerVersionId` (đọc lúc chạy từ binding `version_metadata` — đây mới là bằng chứng bản đang phục vụ), `workerVersionUploadedAt`. Giá trị lạ bị đổi thành `unknown`/`null`, không phản chiếu chuỗi tuỳ ý, không lộ biến môi trường. Đã kiểm trên workerd cục bộ với binding thật: trả `commit` = HEAD và một `workerVersionId` do runtime cấp.
- Sau khi bạn cho phép deploy: `curl -s https://security.tridinhbui0901.workers.dev/api/version` rồi đối chiếu `workerVersionId` với tab Deployments (phiên bản **Active**) trên dashboard và với Version ID trong check Workers Builds. Khi trùng cả ba mới được tuyên bố “production = commit X”. Lưu ý: nếu build chạy ngoài Workers Builds, `commit` có thể là `unknown`.
- **Kết quả sau khi push `a1b6fa4` (2026-10-17 ~20:35Z):** `GET /api/version` trên production trả `commit: a1b6fa46eebd8d438f1f5f6598c7d36c1b8d94a2`, `builtAt: 2026-10-17T20:29:50Z`, `workerVersionId: 6311c79b-e40e-41bd-9bff-16c6c3e03119`, `workerVersionUploadedAt: 2026-10-17T20:31:46Z`. `commit` được nhúng lúc build và `workerVersionId` do runtime Cloudflare cấp cho request này, nên đây là bằng chứng trực tiếp rằng **production đang phục vụ bản dựng của `a1b6fa4`**. `/demo` 200, `/admin/giai-thich` 404, `/api/admin/metrics` 401.
- **Điểm chưa giải thích được:** check “Workers Builds” của cả `f718cf0` và `a1b6fa4` báo **failure** dù bản dựng `a1b6fa4` rõ ràng đã được phục vụ. Nghĩa là trạng thái check trên GitHub **không** phản ánh đúng việc deploy; có thể một bước sau khi tải phiên bản lên (ví dụ bước deploy/triển khai container) báo lỗi, hoặc Version ID tiếp tục không xuất hiện trong tóm tắt check. Nguyên nhân cần đọc nhật ký ở dashboard (Build ID `79927e71-bbb5-4c00-af46-d89a4543cdd0`); chưa kiểm tra được. Chưa đối chiếu `workerVersionId` với tab Deployments (cần dashboard).
- Mỗi commit tài liệu đẩy lên `main` lại tạo bản dựng mới và đổi `commit` trong `/api/version`; con số ở trên là ảnh chụp tại thời điểm `a1b6fa4`.
- Không deploy lại thủ công.

**Hồi quy trên Worker runtime thật (workerd, `wrangler dev --local`):** `decodeUtf8` (module `fetch.ts` đóng gói nguyên bản) so với `Buffer#toString("utf8")` của Node trên 412 vector (BOM, byte lỗi, overlong, surrogate, cắt giữa chừng, tiếng Việt/emoji, 400 mẫu ngẫu nhiên; mỗi vector còn đọc qua `subarray` của vùng nhớ lớn hơn): **0 sai khác**. Preview Worker đã build (`opennextjs-cloudflare preview`): `/demo` 200, `/admin`, `/admin/giai-thich`, `/api/admin/chat/*`, `/api/admin/help-requests/*` ẩn danh → 404; `/api/admin/metrics` không token → 401; bình chọn thiếu Origin → 403, `ruleId` lạ → 400, body > 4 KB → 413; quét `127.0.0.1`, `169.254.169.254`, `[::1]`, `10.0.0.1` bị từ chối `non_public_ip`, cổng 22 bị `port_not_allowed`. Bộ test SSRF/DNS/redirect (227 test) vẫn đạt. Chưa kiểm thử tích hợp GitHub thật (cần token OAuth); chỉ có test đơn vị.

## 8. Audit nội dung (đợt này)

- **Lỗi chatbot:** nút gợi ý “Có chắc là đúng không?” (chính chip do chatbot đưa ra) không khớp từ khoá nên rơi vào câu trả lời mặc định, bỏ qua độ tin cậy. Đã sửa và thêm test; câu trả lời nay nêu **mức chắc chắn + giới hạn bằng chứng** (`certainty`/`caveat`).
- **Lời giải thích điểm:** khi 0 vấn đề, câu cũ “Tốt lắm” dễ bị hiểu là an toàn; nay nói rõ “không có nghĩa là website an toàn tuyệt đối”, và mức ≥ 80 điểm ghi “điểm cao không phải bảo chứng an toàn”. Test chặn các cụm “an toàn tuyệt đối/không thể bị hack” khi được dùng như lời bảo chứng.
- **Giải thích tổng quát của chatbot (Feynman):** với phát hiện tiềm năng/chưa kết luận, nay kèm dòng “Lưu ý: <caveat>” thay vì chỉ ví von.
- **Phân biệt kỹ thuật và suy luận:** mỗi giải thích có `certainty` (đã xác nhận / tiềm năng / chưa đủ dữ liệu) và test chặn các cụm khẳng định tuyệt đối trong cả 63 luật.
- **Giới hạn đã biết, chưa sửa:** (1) ngưỡng “hạn chứng chỉ quá dài” của luật là 398 ngày trong khi ngành đang rút ngắn (từ 2026) — luật có thể bỏ sót chứng chỉ 200–398 ngày; đã làm mềm lời giải thích, **chưa đổi luật** vì đổi ngưỡng ảnh hưởng điểm/benchmark; (2) ACAO `*` không credentials vẫn tính “fail” mức thấp; (3) `Feynman` ví von vẫn là văn bản chung theo luật, chưa theo biến thể; (4) tỉ lệ đoán “cookie phiên” dựa trên tên cookie.
- **Chưa làm được:** chưa có người thật đánh giá nên chưa biết mục nào *thực sự* gây hiểu sai; danh sách trên là rà soát của người viết, không thay thế user testing.

## 9. User testing

**Chưa thực hiện** — không có người tham gia nào, không có dữ liệu. Đã chuẩn bị: [docs/user-testing/README.md](./user-testing/README.md) (5 nhiệm vụ, thang chấm, tiêu chí), [consent-and-briefing.md](./user-testing/consent-and-briefing.md), phiếu quan sát [observations.csv](./user-testing/observations.csv) (chỉ có tiêu đề) và công cụ tổng hợp `scripts/usertest-summary.ts` (có test bằng fixture ghi rõ “không phải kết quả thật”). Nó chỉ báo số đếm, không tính phần trăm cho mẫu 5 người.

## 10. Kiểm thử đợt này

`npm run typecheck` sạch; vitest 41 file / 939 test đạt; `build:cf` + `wrangler deploy --dry-run` thành công, binding `CF_VERSION_METADATA` được nhận.
