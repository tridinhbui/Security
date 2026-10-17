# Báo cáo Phase 3.2 — Kiểm chứng người dùng thật và hệ thống phản hồi

**Trạng thái: CHƯA HOÀN TẤT — chờ buổi thử nghiệm với người thật.** Phần kỹ thuật đã xác minh; phần cần người tham gia (mục 4–8 của yêu cầu) **chưa thực hiện** và **không có số liệu nào được bịa**.

Cập nhật: `2026-10-17T23:26Z` (Phase 3.4). Nhánh review: `phase-3.2-release-ready` (tách từ `a1b6fa4`, chỉ chứa thay đổi Phase 3.2). **Chưa merge, chưa deploy, chưa thay đổi D1 production.**

## Phase 3.4 — Giải quyết blocker & kiểm chứng cuối (cập nhật mới nhất)

**Vẫn NO-GO production.** PR #2 vẫn Draft. Không merge, không deploy, không ghi D1 production.

| # | Mục | Trạng thái | Chi tiết |
|---|---|---|---|
| 1 | Workers Builds failure | **BLOCKED** | Build của đầu PR (`f0943bfb-6eb4-42c4-af5e-6016849e43be`) và của nhánh trước (`cd3d2a81-…`) cũng failure, không tải phiên bản mới. Công cụ Cloudflare Builds chưa được uỷ quyền; không có cách đọc log ngoài dashboard. Hướng dẫn lấy log ở checklist cuối. Không đoán nguyên nhân, không đổi cấu hình. |
| 2 | Docker dry-run | **PASS** | Docker chạy được (CLI ở `/Applications/Docker.app/Contents/Resources/bin`, chưa nằm trong PATH). `wrangler deploy --dry-run` trên nhánh PR thành công: image `vibesec-scannercontainer` dựng được, các binding (D1, Queue, DO, `CF_VERSION_METADATA`, biến môi trường) hợp lệ; `Total Upload: 14556 KiB / gzip: 3400 KiB` (< 64 MiB). Không deploy. Việc này cho thấy cấu hình Worker/Container hợp lệ khi dựng cục bộ; **không** chứng minh Workers Builds sẽ thành công. |
| 3 | Admin QA | **NEEDS HUMAN VALIDATION** | Checklist E2E mới: `docs/admin-qa-checklist.md` (4 trường hợp quyền, trạng thái 0 dữ liệu, thống kê, mobile). Tôi không đăng nhập admin production và không tạo phiếu. |
| 4 | Bảo mật phiếu | **PASS** (P0) / rủi ro còn lại được ghi | Chứng minh được và đã chặn: một người tự tạo tới 60 “phiếu” cho một luật bằng cách bịa `variant` → giới hạn 5 biến thể/luật/người; gửi lại y hệt không ghi thêm. IP xoay vòng/IP dùng chung: không có biện pháp P0 không phá UX/riêng tư — xem §16. |
| 5 | Quy trình user testing | **Hoàn thiện, chưa thực hiện** | Thêm kế hoạch phân tích đăng ký trước (`docs/user-testing/README.md` §8): đơn vị, ngưỡng “đủ để quyết định”, điều kiện xếp hạng, dừng sớm. Chưa có người tham gia; **không có feedback hay xếp hạng**. |
| 6 | Content QA | **PARTIAL — NEEDS HUMAN VALIDATION** | Audit độc lập (một agent đọc lại cả 63 luật; con số “39” trong yêu cầu không khớp mã nguồn, có **63** luật) tìm 35 mục. Tôi kiểm chứng và **đã sửa 9 nhóm** (xem §17); phần còn lại chưa áp dụng và nằm trong danh sách mở. Nguồn chuẩn tôi không tự đọc được trong lượt này nên một số điểm cần người có chuyên môn xác nhận. |
| 7 | Final gate | **PASS** | typecheck sạch · **979 test pass / 0 fail / 0 skip** (44 file) · `npm run build` OK · dry-run OK. Regression trình duyệt: UI không đổi so với lượt đo trước, không đo lại. |

### Checklist chủ repo (cập nhật)
- [ ] **Lấy log Workers Builds** (BLOCKED): dashboard Cloudflare → Workers & Pages → `security` → *Deployments/Builds* → mở Build ID `f0943bfb-6eb4-42c4-af5e-6016849e43be` (và `79927e71-bbb5-4c00-af46-d89a4543cdd0`, `cd3d2a81-9af9-4d49-b94f-74bae064716e`) → chép **tên bước đỏ + 20 dòng log quanh lỗi** (che token/secret). So sánh với một build `success` cũ, ví dụ của `e02e4cb`. Ghi thêm *Build command*, *Deploy command*, và *Branch control* ở Settings → Builds. Hoặc uỷ quyền MCP Cloudflare Builds cho session.
- [ ] Đối chiếu `workerVersionId` `6311c79b-e40e-41bd-9bff-16c6c3e03119` với phiên bản **Active**.
- [ ] Thực hiện `docs/admin-qa-checklist.md` bằng tài khoản admin thật.
- [ ] Chạy buổi thử nghiệm 3–5 người (≥ 1 nhóm C) theo `docs/user-testing/`.
- [ ] Người có chuyên môn security xác nhận §17 (đặc biệt: mốc 200 ngày chứng chỉ từ 15/03/2026 và các mục “chưa áp dụng”).
- [ ] Quyết định về Turnstile (rủi ro IP xoay vòng, §16).
- [ ] Chỉ khi các mục trên xong mới xem xét Ready for Review → merge → deploy.

## Phase 3.3 — Final Security Review & User Validation (cập nhật)

**Giữ NO-GO production.** PR #2 vẫn Draft, 15 file, chưa merge; `/api/version` vẫn `a1b6fa4`; production vẫn **0 phiếu**.

### Kết quả mới của Phase 3.3
| Mục | Trạng thái | Chi tiết |
|---|---|---|
| 1. Final PR review | **PASS** (sau khi sửa 1 lỗi tôi tự tìm ra) | CI GitHub `test` xanh (2/2). Tương thích `a1b6fa4`: là tổ tiên của đầu PR, merge sạch (MERGEABLE). Review toàn bộ diff `src/`: **tìm thấy lỗi thật trong `voterNet` (IPv6 /64) do chính PR này đưa vào**: IPv4 nhúng trong IPv6 (`::ffff:1.2.3.4`) bị gom hết về `0:0:0:0::/64`, tức mọi người dùng dạng đó thành *một* người bình chọn (đếm thiếu + dùng chung giới hạn 60/giờ). Đã sửa: dạng nhúng IPv4 được trả về địa chỉ IPv4; bỏ zone id `%eth0`; +2 test (23 test route). Production Cloudflare thường đưa IPv4 thuần nên lỗi này khó gặp, nhưng là lỗi thật. Rate limit, CSRF, riêng tư, quyền admin: không đổi so với §12, không tìm thấy lỗi mới. |
| 2. Workers Builds | **BLOCKED** | Công cụ Cloudflare Builds chưa được uỷ quyền trong session này, `wrangler` không có lệnh đọc nhật ký bản dựng. Không đoán, không đổi cấu hình. Bằng chứng mới: **nhánh PR `cd0f4f0` cũng bị check “Workers Builds” báo failure (Build ID `cd3d2a81-9af9-4d49-b94f-74bae064716e`) và KHÔNG có phiên bản Worker mới nào được tải lên** (phiên bản mới nhất vẫn `6311c79b…`), nên bản dựng nhánh PR không đụng production. Failure này không phải riêng bản dựng trên `main`. |
| 3. Timestamp migration 0011 | **PASS (đã giải thích)** | Không bất thường; xem §11. Không sửa lịch sử. |
| 4. Thử nghiệm người thật | **NEEDS HUMAN VALIDATION** | Bộ công cụ đã sẵn sàng (`docs/user-testing/`); **chưa có người tham gia nào**, tôi không điều phối được và không tạo/giả phản hồi. Xem checklist. |
| 5. UX trên admin thật | **NEEDS HUMAN VALIDATION** (admin) · **PASS** (mobile) | Cần tài khoản Google admin để vào `/admin/giai-thich` trên production — tôi không đăng nhập thay. Mobile 375px: bình chọn 40px, chatbot textarea tự giãn, không tràn ngang (đo lượt Phase 3.2; các tệp UI không đổi từ đó). |
| 6. Phân tích phản hồi | **BLOCKED (không đủ dữ liệu)** | 0 phiếu, 0 người tham gia ⇒ **không xếp hạng** 5 giải thích khó hiểu nhất. Quy tắc: dưới 10 phiếu mỗi nhóm = “mẫu nhỏ”; 0 phiếu ≠ “dễ hiểu”. |
| 7. Final gate | **PASS** (trừ Docker dry-run) | typecheck sạch · **970 test pass / 0 fail / 0 skip** (43 file) · `npm run build` OK · browser regression: textarea/nút bình chọn/tràn ngang đo lại ở Phase 3.2 (UI không đổi). **Chưa xác minh:** `wrangler deploy --dry-run` đầy đủ (cần Docker CLI để dựng image container, máy này không có). |

### Checklist cho chủ repo (cần làm, theo thứ tự)
- [ ] Mở nhật ký bản dựng trên dashboard Cloudflare: Build ID `79927e71-bbb5-4c00-af46-d89a4543cdd0` (a1b6fa4), `cd3d2a81-9af9-4d49-b94f-74bae064716e` (nhánh PR) và bản của `f718cf0`; chép lại **bước nào đỏ và thông báo lỗi** (không dán token/secret). Hoặc uỷ quyền công cụ Cloudflare Builds cho session.
- [ ] Đối chiếu `workerVersionId` `6311c79b-e40e-41bd-9bff-16c6c3e03119` với tab Deployments (phiên bản **Active**).
- [ ] Vào `/admin/giai-thich` bằng tài khoản admin (email trong `ADMIN_EMAILS` + đã liên kết Google) trên điện thoại và máy tính; ghi lại nếu bảng “Theo chế độ hiển thị” hoặc cổng 404 cho người không phải admin hoạt động sai.
- [ ] Tuyển 3–5 người (≥ 3 không kỹ thuật, ≥ 1 có chuyên môn security, độc lập với đội phát triển) và chạy buổi theo `docs/user-testing/facilitator-runsheet.md`; điền `observations.csv` bằng dữ liệu thật.
- [ ] Người nhóm C điền `security-reviewer-sheet.md` cho các luật đã viết lại ở `1e73d61`.
- [ ] Chấp nhận hoặc từ chối rủi ro bình chọn ở §12 (IP dùng chung / IP xoay vòng / không CAPTCHA).
- [ ] Cài Docker (hoặc dùng CI có Docker) để chạy `wrangler deploy --dry-run` trước khi deploy.
- [ ] Chỉ sau các mục trên mới quyết định **Ready for Review → merge → deploy**; kiểm tra `/api/version` sau deploy.

## Kết luận release-ready (Phase 3.2): PASS / BLOCKED / NEEDS HUMAN VALIDATION

### PASS (có bằng chứng trong báo cáo này)
| Hạng mục | Bằng chứng |
|---|---|
| Phạm vi PR sạch | Nhánh `phase-3.2-release-ready` = `a1b6fa4` + commit Phase 3.2; **không** chứa `94c33bd` (tài liệu xác minh production của session khác, nhánh `docs/production-verification-a1b6fa4` của họ không bị chạm) — §10 |
| Schema `explain_feedback` trên production khớp migration 0011 | Truy vấn chỉ-đọc: 10 cột, ràng buộc CHECK/UNIQUE, 2 chỉ mục đều trùng tệp SQL; `d1_migrations` có đủ 11/11 tệp, không dư/thiếu — §11 |
| Bảo mật API bình chọn | 23 test route (CSRF, đầu vào, riêng tư, trùng, giới hạn, 413 theo độ dài thật, IPv6 /64, IPv4 nhúng trong IPv6) — §2, §12 |
| Giới hạn kích thước Worker | **Không còn là blocker**: Cloudflare đã bỏ giới hạn nén (3 MB/10 MB) từ 2026-09-04; chỉ còn 64 MiB chưa nén cho mọi gói. Bundle hiện ≈ 14,9 MB chưa nén — §13 |
| UX | Đo trong trình duyệt: textarea tự giãn 42→116→166px (trần 168) ở 1280 và 375px; nút bình chọn 40px ở 375px (32px ở desktop); không tràn ngang; hộp chatbot nằm trọn khung nhìn — §14 |
| Kiểm tra toàn bộ | typecheck (2 tsconfig) sạch · **970 test pass / 0 fail / 0 skip** (43 file) · `npm run build` (OpenNext) thành công — §8 |
| Bộ thử nghiệm | Có thêm phiếu điều phối + phiếu rà soát kỹ thuật cho nhóm C; công cụ tổng hợp cảnh báo khi chưa có nhóm C — §3 |

### BLOCKED (không làm được nếu thiếu thứ từ bên ngoài)
| Hạng mục | Chặn bởi |
|---|---|
| Nguyên nhân Workers Builds báo *failure* | Cần **nhật ký bản dựng ở dashboard Cloudflare** (Build ID `79927e71-bbb5-4c00-af46-d89a4543cdd0`, và bản của `f718cf0`); công cụ Cloudflare MCP trong session này chưa được uỷ quyền — §9 |
| Mục 4–8 (người thật, xếp hạng 5 giải thích khó hiểu, kiểm tra sai ý nghĩa) | Production vẫn có **0 phiếu** và 0 người tham gia. **Không xếp hạng**, không viết lại 63 giải thích — §5, §6 |
| `wrangler deploy --dry-run` đầy đủ | Cần Docker CLI để dựng image container; máy này không có. Bước đóng gói Worker (bundling) đã chạy được — §13 |

### NEEDS HUMAN VALIDATION
| Việc | Ai |
|---|---|
| Đọc nhật ký bản dựng Cloudflare và xác nhận vì sao check *failure* dù phiên bản đã được phục vụ; đối chiếu `workerVersionId` `6311c79b-…` với tab Deployments (Active) | Chủ repo/tài khoản Cloudflare |
| Xem `/admin/giai-thich` bằng tài khoản admin thật trên production (chỉ kiểm cổng admin ở local) | Admin |
| Chạy buổi thử nghiệm 3–5 người (≥ 1 người nhóm C) theo `docs/user-testing/` | Người điều phối |
| Rà soát kỹ thuật các giải thích đã viết lại ở `1e73d61` | Người nhóm C |
| Chấp nhận rủi ro phiếu bầu còn lại (§12) hoặc yêu cầu Turnstile | Chủ sản phẩm |

### Điều kiện để merge/deploy (đề xuất)
1. Chủ repo duyệt PR; CI GitHub (`test`) xanh.
2. Quyết định có chấp nhận rủi ro §12 hay không (không bắt buộc Turnstile ở giai đoạn thử nghiệm nhỏ).
3. Trước khi bật cho người dùng thật rộng: nhật ký bản dựng đã được đọc, để biết lỗi Workers Builds có phải lỗi thật không.
4. Sau deploy: `curl /api/version` phải trả đúng commit; không coi check Workers Builds là bằng chứng. **Không có thay đổi D1 trong PR này.**
5. Không dùng kết quả PR này để tuyên bố giải thích “dễ hiểu hơn”: chưa có dữ liệu người dùng.

## 0. Tóm tắt trung thực

| # | Yêu cầu | Trạng thái | Bằng chứng / lý do |
|---|---|---|---|
| 1 | Xác minh migration 0011, API, `/admin/giai-thich` trên production | **Đã xác minh** (có giới hạn, xem §1) | Truy vấn chỉ-đọc + probe không ghi |
| 2 | Quyền admin, CSRF, rate limit, riêng tư, chống trùng | **Đã kiểm thử** — production (CSRF, đầu vào, quyền ẩn danh) và test/local (phần còn lại) | §2 |
| 3 | Chuẩn bị bài kiểm thử 3–5 người | **Đã có** (`docs/user-testing/`, từ phiên làm việc trước); chưa chạy | §3 |
| 4 | Người thật scan, đọc 3 phát hiện, tìm cách sửa, đánh giá | **CHƯA THỰC HIỆN** (0 người) | Cần tuyển người |
| 5 | Đo task completion, thời gian, mức hiểu, tỉ lệ “Chưa” | **Công cụ sẵn sàng, 0 dữ liệu** | §3, §5 |
| 6 | Phân tích theo rule, variant, chế độ | **Công cụ sẵn sàng** (đã bổ sung chiều “chế độ”); **0 phiếu thật** | §5 |
| 7 | Chọn và viết lại 5 giải thích khó hiểu nhất **có đủ bằng chứng** | **KHÔNG THỰC HIỆN — không đủ bằng chứng** | §6 |
| 8 | Kiểm tra không sai ý nghĩa kỹ thuật | **Chưa thể** (không có đoạn viết lại theo dữ liệu thật; cần nhóm C rà soát) | §6 |
| 9 | Regression tests, desktop/mobile | **Đã làm**; tìm và sửa 2 lỗi thật | §4 |
| 10 | Báo cáo này | Đã lập | — |

## 1. Production: những gì đã xác minh (không dựa vào “Workers Builds thành công”)

Không coi trạng thái Workers Builds là bằng chứng. Phiên làm việc khác đã ghi nhận check “Workers Builds” báo *failure* dù bản dựng đã được phục vụ. Bằng chứng dưới đây lấy từ chính production:

- `GET /api/version` → `{"commit": "a1b6fa46eebd8d438f1f5f6598c7d36c1b8d94a2", "builtAt": "2026-10-17T20:29:50.267Z", "workerVersionId": "6311c79b-e40e-41bd-9bff-16c6c3e03119", "workerVersionUploadedAt": "2026-10-17T20:31:46.901896Z"}`. Commit này **bằng** đầu `origin/main` lúc kiểm tra (`a1b6fa4`), và `28344ad` (API bình chọn) là tổ tiên của nó.
- **D1 production** (truy vấn chỉ-đọc): bảng `explain_feedback` và hai chỉ mục (`explain_feedback_rule_idx`, `explain_feedback_voter_idx`) **tồn tại**; `d1_migrations` có `['0011_explain_feedback.sql']`.
- **Số phiếu thật trên production: 0** (đo trước và sau các probe, không đổi).
- Probe **không ghi** (đều bị chặn trước khi vào cơ sở dữ liệu):
  - POST thiếu `Origin` → 403; `Origin: https://evil.example` → 403 (route đã deploy, CSRF hoạt động);
  - `Origin` đúng + `ruleId` không tồn tại → 400; + `verdict` lạ → 400;
  - `/admin/giai-thich` ẩn danh → 404; giao diện bình chọn có trong HTML server của `/demo` (6 lần xuất hiện câu hỏi).

**Điều cần nói rõ:** migration 0011 được áp lên production bằng `wrangler d1 execute --file` rồi **ghi tay** vào `d1_migrations`, không qua `migrations apply`. Kết quả hiện nhất quán (bảng có, bản ghi có), nhưng đây không phải đường chuẩn.

**Không thể xác minh trên production (và vì sao):**
- Giới hạn tốc độ (60 phiếu/giờ) và chống bình chọn trùng: muốn kiểm phải **tạo phiếu thật/giả**, bị cấm. Đã kiểm bằng test trên SQLite thật (§2).
- Trang `/admin/giai-thich` **với quyền admin**: cần đăng nhập Google của admin. Đã kiểm ở local (§2).

## 2. Kiểm tra bảo mật (test tự động + local)

`src/lib/__tests__/explain-feedback-route.test.ts` (18 test, chạy trên D1/SQLite thật trong bộ nhớ, gọi thẳng route handler):

| Kiểm tra | Kết quả |
|---|---|
| CSRF: thiếu Origin, Origin lạ, Origin gần giống (`app.test.evil.example`) | 403, không ghi gì |
| Đầu vào: JSON hỏng, luật lạ, thiếu/sai verdict/source, chuỗi kiểu SQL | 400, không ghi gì (câu lệnh tham số hoá) |
| Riêng tư | Không cột nào chứa IP thô, tên miền, URL; biến thể chứa tên miền bị bỏ; `voter_hash` 32 hex (HMAC); bảng chỉ có 10 cột định trước |
| Nhận xét tự do | Tên miền, email, IP, URL, token, số điện thoại bị thay bằng `[đã ẩn]` **trước** khi lưu; nhận xét chỉ lưu khi chọn “Chưa” |
| Chống trùng | Cùng người bình chọn lại = ĐỔI phiếu (1 dòng); người khác = dòng riêng; người đăng nhập tính theo tài khoản (đổi IP không bơm thêm) |
| Giới hạn tốc độ | Phiếu thứ 61 trong giờ → 429; người khác không bị ảnh hưởng |
| Quyền admin | Cổng `getAdmin()` đứng trước `getDb()` ở mọi trang admin (kiểm bằng mã nguồn) |

**Local, đăng nhập thật qua cookie phiên (DB local, không phải production):** `/admin/giai-thich` → ẩn danh **404**; người dùng thường **404**; email admin **không** liên kết Google **404**; email admin **có** liên kết Google **200**.

### Hạn chế đã biết (không phải lỗi, cần ghi nhận)
1. **Người ẩn danh cùng IP công cộng (văn phòng, trường học) dùng chung một phiếu** cho mỗi (luật, biến thể) → có thể đếm thiếu.
2. **Chống bơm phiếu yếu với kẻ cố ý đổi IP**: không có CAPTCHA. Đủ để ngăn nhấn nhầm hai lần, **không** đủ chống thao túng có chủ đích. Vì vậy dashboard chỉ có giá trị tham khảo khi số phiếu lớn và kết hợp quan sát trực tiếp.
3. Biến thể có tên miền bị gộp về rỗng → hai phát hiện khác nhau của cùng luật có thể dùng chung một phiếu.

## 3. Bộ thử nghiệm với người thật (đã có, chưa chạy)

`docs/user-testing/` (README, consent-and-briefing, `observations.csv` chỉ có hàng tiêu đề) và `scripts/usertest-summary.ts`:
- 5 người: 3 nhóm A (không kỹ thuật, **nhóm chính**), 1 nhóm B, 1 nhóm C (chuyên môn, kiểm tra sai kỹ thuật).
- 5 nhiệm vụ: T1 scan · T2 đọc 3 phát hiện và giải thích · T3 ưu tiên · T4 tìm bước sửa **và** cách kiểm tra lại · T5 bấm 👍/🤔 thật.
- Ánh xạ sang chỉ số bạn yêu cầu:

| Chỉ số | Cột trong `observations.csv` | Cách tính |
|---|---|---|
| Task completion | `completed` (0/1) theo từng nhiệm vụ | Số người hoàn thành / số người làm (báo **số đếm**, ví dụ 3/5) |
| Thời gian tìm hướng dẫn | `seconds` ở **T4** | Trung vị theo nhiệm vụ |
| Mức hiểu đúng | `understanding` (0/1/2), `owner_correct`, `fix_found`, `verify_known` | Trung bình theo luật; cờ `fix-first`/`review`/`insufficient` |
| Tỉ lệ “Chưa” | `clarity_vote` + bảng `explain_feedback` | Admin dashboard: chỉ kết luận khi ≥ 10 phiếu và cận dưới Wilson 95% ≥ 30% |

Quy tắc đã cài vào công cụ: với ≤ 5 người **chỉ báo số đếm, không báo phần trăm**; luật có < 2 người đọc là `insufficient`.

## 4. Lỗi thật tìm thấy và sửa trong đợt này

1. **Ô nhập chatbot không bao giờ tự giãn (lỗi của tôi ở Phase 2).** Lớp `!h-auto` (`!important`) đè lên chiều cao do JS gán: nội dung 14 dòng vẫn chỉ cao 44px. Lần kiểm tra trước chỉ đo giới hạn ký tự nên bỏ sót. Sau sửa đo trong trình duyệt (px CSS): 1 dòng 44 → 4 dòng 118 → 14 dòng tối đa 168 rồi cuộn trong ô. Có test hồi quy.
2. **Nút bình chọn chỉ cao 32px trên điện thoại** (dưới mức 40–44px nên dùng cho cảm ứng). Nay 40px trên điện thoại, 32px từ màn hình `sm`. Có test hồi quy.
3. **Thiếu chiều “chế độ hiển thị”** trong phân tích: đã thêm bảng *Dễ hiểu × Kỹ thuật* theo luật, mỗi ô tự áp quy tắc mẫu nhỏ (dưới 10 phiếu: chỉ hiện số đếm, nhãn “mẫu nhỏ”).

**Kiểm tra giao diện (đo bằng trình duyệt):** 375px (điện thoại) và 1024px (desktop): không tràn ngang trên `/demo` và `/admin/giai-thich`; bảng admin cuộn trong khung; hộp chatbot nằm trọn trong khung nhìn; bộ đếm ký tự hiện từ 1500. **Giới hạn:** ảnh chụp màn hình trong chế độ giả lập điện thoại không đáng tin nên kết luận dựa trên số đo, chưa có kiểm tra thủ công trên thiết bị thật.

## 5. Dữ liệu thật hiện có

| Nguồn | Số lượng |
|---|---|
| Người tham gia thử nghiệm | **0** |
| Phiếu “giải thích có rõ không?” trên production | **0** |
| Nhận xét từ người dùng thật qua bình chọn | **0** |

Nên **không có phân tích theo luật/biến thể/chế độ nào để báo cáo**, và không được suy ra gì về mức hiểu của người dùng.

## 6. Vì sao KHÔNG chọn và viết lại 5 giải thích (mục 7–8)

Yêu cầu là chọn 5 phần khó hiểu nhất **có đủ bằng chứng**. Hiện **không có bằng chứng nào** (0 người, 0 phiếu). Nếu chọn bây giờ thì chỉ là phỏng đoán, nên tôi **không chọn và không viết lại**. Hai điều cần lưu ý:
- Có **một nguồn phản hồi thật duy nhất**: góp ý của một người dùng ngoài (headers chung chung, thiếu giải thích bằng chứng, chatbot giới hạn chữ). Phản hồi này đã được xử lý ở Phase 1–2.
- Phiên làm việc trước đã **viết lại giải thích cho 63/63 luật** (commit `1e73d61`, báo cáo `docs/explanation-qa-report.md`) dựa trên rà soát nội dung, **không** dựa trên dữ liệu người dùng. Cần coi đó là **giả thuyết cần kiểm chứng** bằng buổi thử nghiệm, và nhóm C (chuyên môn) cần rà soát độ chính xác kỹ thuật (mục 8) trước khi tin.

## 7. Cải tiến đề xuất (chưa làm)
1. **Chạy buổi thử nghiệm** theo `docs/user-testing/README.md` trước khi viết lại thêm bất cứ giải thích nào.
2. Nếu cần chống thao túng phiếu: Cloudflare Turnstile cho `/api/explain-feedback` ở người dùng ẩn danh.
3. Dùng `/api/version` làm bước bắt buộc trong quy trình phát hành (so `commit` với `main`), vì trạng thái check Workers Builds hiện không đáng tin.
4. Khi có ≥ 10 phiếu cho một mục: dùng cột *theo chế độ* để quyết định viết lại cho người mới hay cho người kỹ thuật.
5. (Tuỳ chọn) giảm bundle bằng cách loại bản `undici`/`iconv` bị đóng gói **hai lần** — xem §13. Không cần thiết để phát hành.

## 8. CI (cục bộ, trước khi xin phê duyệt)
- `npm run typecheck` (cả hai tsconfig): sạch.
- `npx vitest run`: **970 passed (970), 0 skipped, 0 failed** (43 file).
- `npm run build` (OpenNext) + `wrangler deploy --dry-run`: thành công, không lỗi.
- `wrangler deploy --dry-run` đầy đủ **không chạy được** ở máy này (cần Docker CLI để dựng image container); bước đóng gói Worker thì chạy được (§13).
- Chưa deploy. Không có commit nào được đẩy lên `main`.

## 9. Workers Builds báo failure (điều tra, chưa kết luận được nguyên nhân)

Bằng chứng thu thập (chỉ đọc, từ GitHub API và `wrangler versions/deployments list`):
- Lịch sử check “Workers Builds: security” trên `main`: `success` đến hết `e02e4cb`; **`failure` ở `f718cf0` và `a1b6fa4`**; `7a0f33e` và `2ad1d3d` không có check (bị bản dựng sau thay thế).
- **`f718cf0` chỉ sửa tài liệu** (`docs/explanation-qa-report.md`) so với `e02e4cb` (đã `success`). Vậy lỗi **không do mã của commit đó**.
- Cả hai lần failure, **phiên bản Worker đã được tải lên và triển khai 100% trước khi check kết thúc**: `c101a829…` lúc 20:14:09Z (check 20:14:52Z) và `6311c79b…` lúc 20:31:46Z (check 20:32:29Z), nguồn `Upload`, “Automatic deployment on upload”. Check được ghi ~43 giây sau khi bản được tải lên, và `started_at == completed_at`.
- `/api/version` khớp commit `a1b6fa4` và `workerVersionId` `6311c79b…`, đúng với danh sách deployments.
- Check không có `annotations`, `output.text` rỗng, chỉ có Build ID và liên kết dashboard.

Suy luận (**chưa được xác minh**): một bước *sau* khi tải phiên bản lên (ví dụ bước triển khai container/đẩy image, hoặc bước hậu kiểm của Workers Builds) trả về lỗi, trong khi chính bản Worker đã được phục vụ. Không giải thích được vì sao `e02e4cb` (cũng có bước này) thì thành công. Cũng chưa loại trừ nguyên nhân phía Cloudflare/tạm thời.

**Phân biệt trạng thái:** check GitHub `test` (CI) = xanh = mã đạt kiểm thử; check “Workers Builds” = **không đáng tin** làm bằng chứng deploy trong tình trạng này; bằng chứng deploy duy nhất tin được là `/api/version` + tab Deployments.

**Thông tin cần chủ repo cung cấp:** nhật ký đầy đủ của Build ID `79927e71-bbb5-4c00-af46-d89a4543cdd0` (a1b6fa4) và của bản dựng `f718cf0` (tìm bước nào đỏ); tab Deployments ở dashboard; cài đặt Build command/Deploy command hiện tại.

## 10. Phạm vi PR (mục 1)
- `94c33bd` (ở nhánh cũ `phase-3.2-validation`) chỉ sửa `docs/explanation-qa-report.md` (+3 dòng xác minh production); session khác đã giữ bản của họ ở nhánh `docs/production-verification-a1b6fa4` (`a3d19ac`, `7c98864`). Tôi **không** sửa nhánh/tệp đó.
- Nhánh review mới `phase-3.2-release-ready` dựng trong worktree riêng từ `a1b6fa4`, cherry-pick commit Phase 3.2 (không dính `94c33bd`). Nhánh cũ `phase-3.2-validation` được giữ nguyên, không đẩy lên.
- Nội dung PR: route/hạ tầng bình chọn (tăng cường nhẹ), bảng theo chế độ ở admin, hai sửa UX, test, tài liệu thử nghiệm, báo cáo này. **Không có migration mới, không đổi scanner/chatbot logic.**

## 11. Kiểm toán D1 (chỉ đọc)
- `sqlite_master` của production cho `explain_feedback`: 10 cột `id, rule_id, variant, verdict, source, mode, comment, voter_hash, created_at, updated_at`; `CHECK` trên `verdict`/`source`; `UNIQUE (voter_hash, rule_id, variant)`; chỉ mục `explain_feedback_rule_idx (rule_id, verdict)` và `explain_feedback_voter_idx (voter_hash, updated_at)`. **Trùng từng ký tự** với `migrations/0011_explain_feedback.sql`.
- `d1_migrations`: 11 dòng, tên khớp đúng 11 tệp trong `migrations/` (không dư, không thiếu).
- `0009_quick_scan.sql` có id 8 và `0008_project_scans.sql` id 9 (áp dụng ngược thứ tự, đã biết từ trước, không ảnh hưởng vì không phụ thuộc nhau).
- **Dấu thời gian `0011` = `2026-10-11 17:06:26` — ĐÃ GIẢI THÍCH, không bất thường** (Phase 3.3, truy vấn chỉ-đọc + git): cột `applied_at` là `DEFAULT CURRENT_TIMESTAMP` (UTC) nên là thời điểm thật của lệnh chèn; commit của tính năng bình chọn `28344ad` có thời điểm `2026-10-11T13:06:27-04:00` = **17:06:27Z**, đúng 1 giây sau; hai phiên bản Worker `6a0e7048…` (17:04:48Z) và `71c3ee53…` (17:10:23Z) bao quanh nó. Nhận định trước đó của tôi (“việc áp migration diễn ra gần đây”) là **sai**: nó được áp ngày 11/10 khi làm tính năng 3.1. Lịch sử migration không bị sửa.
- Không chạy lại migration, không sửa dữ liệu.

## 12. Rà soát bảo mật cơ chế bình chọn (mục 2)
| Cơ chế | Đánh giá |
|---|---|
| 1 phiếu / (người, luật, biến thể) | Đúng: ràng buộc `UNIQUE` + upsert. Bình chọn lại = đổi phiếu. |
| Định danh người bình chọn | Đăng nhập: HMAC(`explain-voter`, user.id). Ẩn danh: HMAC(IP). Không lưu IP thô; không thu thập thêm dữ liệu cá nhân. |
| 60 phiếu/giờ | Đếm **dòng** cập nhật trong 1 giờ, không đếm lần gọi: đổi đi đổi lại **cùng một mục** không bị giới hạn (chỉ tốn ghi D1). Kiểm tra “đếm rồi mới ghi” không nguyên tử: một loạt yêu cầu song song có thể vượt 60 một ít. Cả hai đều rủi ro thấp (chi phí/nhiễu, không ảnh hưởng quyền). |
| CSRF | `sameOrigin` (Origin phải khớp Host); thiếu/lệch/gần giống đều 403. |
| Quyền admin | Dashboard và API admin: `getAdmin()` (email trong `ADMIN_EMAILS` **và** đã liên kết Google), không phải admin → 404. Cổng đứng trước truy vấn DB. |
| Ẩn danh nhận xét | Thay URL/email/IP/tên miền/token/số điện thoại bằng `[đã ẩn]` **trước khi lưu**, chỉ lưu khi chọn “Chưa”, ≤ 300 ký tự. **Giới hạn:** không thể nhận ra tên người/địa chỉ nhà viết bằng chữ thường; vì thế nhận xét chỉ admin xem được và cần có chính sách xoá (đề xuất: xoá nhận xét sau 180 ngày — chưa làm). |
| Kích thước nội dung | **Đã sửa:** trước đây chỉ kiểm `content-length` (vắng khi chunked, hoặc nói dối); nay đo độ dài thật ≤ 4 KB, body không phải đối tượng JSON → 400. |
| IPv6 xoay vòng | **Đã sửa một phần:** nhiều địa chỉ trong cùng `/64` nay tính là một người (một thuê bao thường có cả /64). |

**Rủi ro còn lại (đã đánh giá, chưa xử lý):**
1. **IP dùng chung (văn phòng, trường học, CGNAT)**: nhiều người ẩn danh trùng một “người bình chọn” cho mỗi (luật, biến thể) → **đếm thiếu**, phiếu sau ghi đè phiếu trước. Hướng giảm duy nhất không thêm dữ liệu cá nhân: khuyến khích đăng nhập; không dùng cookie định danh dài hạn vì đó là thêm dữ liệu cá nhân. Hệ quả: số phiếu là **cận dưới**, không phải số người.
2. **IP xoay vòng (proxy/botnet/IPv4 mới mỗi lần)**: kẻ cố ý vẫn bơm được ≤ 60 phiếu/giờ mỗi IP, và có thể tạo biến thể tuỳ ý dạng `[a-z0-9-]{1,32}` (mỗi biến thể là một dòng mới) để làm nhiễu bảng. **Không có CAPTCHA.** Kết luận: dashboard đủ cho phát hiện nhầm lẫn *thiện chí*, **không đủ chống thao túng có chủ đích**. Nếu cần: Cloudflare Turnstile cho người ẩn danh, hoặc danh sách biến thể hợp lệ (allowlist) thay vì regex — chưa làm vì cần đổi hợp đồng giữa giao diện và API.
3. Phiếu thật của người tham gia thử nghiệm sẽ lẫn với phiếu của người dùng bình thường trên production. Cách xử lý: ghi giờ buổi thử (phiếu điều phối) và chỉ đối chiếu, không lọc/sửa dữ liệu thật.

## 13. Kích thước bundle Worker (mục 4)
- **Giới hạn thực tế (tra tài liệu Cloudflare, bản tin 2026-09-04 và trang Limits):** không còn giới hạn dung lượng **nén**; chỉ còn 64 MiB **chưa nén** cho cả Free và Paid. Ghi chú trước đây của tôi (“3,39 MB vượt mốc 3 MB của gói Free”) **đã lỗi thời và sai**; đã bỏ. Còn lại: thời gian khởi động tối đa 1 giây (bundle lớn có thể làm chậm); production đang chạy bình thường.
- Số đo: `index.js` 14,9 MB chưa nén; nén gzip mức 9 ≈ 3,45 MB (wrangler báo ≈ 3,39 MB).
- Nguyên nhân (phân tích metafile của esbuild): 7,66 MB là mã Next đã dựng (`.next/server`), 2,2 MB `next` runtime, phần còn lại nhỏ. Hai khối **1,4 MB giống nhau** (`chunks/ssr/_0c9l_rx._.js` và `chunks/_10t5kkj._.js`, mỗi khối ≈ 436 KB gzip) chứa `undici` + `iconv` kéo vào qua `cheerio` (`src/lib/scanner/parse.ts`) và bị đóng gói **hai lần** (một cho SSR, một cho route). `zod` ≈ 0,5 MB, bộ luật ≈ 0,3 MB.
- **Đề xuất giảm an toàn (chưa làm; cần thử trên workerd):**
  1. Gom `undici`/`iconv` thành một bản (alias chung trong cấu hình bundler) — kỳ vọng giảm ≈ 1,4 MB chưa nén (≈ 0,4 MB nén).
  2. Hoặc chỉ nhập phần của `cheerio` cần cho `load`, thay `undici` bằng stub vì scanner không dùng `fromURL`. **Không** đổi sang `cheerio/slim`: nó dùng `htmlparser2` thay vì `parse5`, có thể làm đổi cách phân tích HTML của các luật bảo mật.
  3. Không loại bỏ luật, SSRF guard hay bất kỳ kiểm tra nào. Mọi thay đổi phải qua: toàn bộ test, 412 vector `decodeUtf8` trên workerd, và quét thử `/demo`.
- Không có nhu cầu cấp bách: chỉ làm khi tiệm cận 64 MiB hoặc khởi động chậm.

## 14. Kiểm tra UX hồi quy (mục 6)
Đo trong trình duyệt tích hợp trên `/demo` (máy phát triển cục bộ, không phải production):
| Kiểm tra | Desktop 1280px | Mobile 375px |
|---|---|---|
| Textarea chatbot tự giãn (1 / 4 / 14 dòng) | 42 / 116 / 166 px (trần 168, rồi cuộn) | 42 / 116 / 166 px |
| Nút 👍 Có / 🤔 Chưa | 32 px | **40 px** |
| Tràn ngang | không | không |
| Hộp chatbot trong khung nhìn | có | có |
Bảng “Theo chế độ hiển thị” và cổng admin: không đo lại trong lượt này (mã trang không đổi); kết quả đo ở §4 và kiểm tra cổng 404/404/404/200 ở §2 vẫn là bằng chứng. **Chưa kiểm tra trên thiết bị thật** và chưa kiểm tra trang admin với dữ liệu nhiều dòng. Phạm vi sửa chỉ chạm `MatMat.tsx` (một className) và `ClarityVote.tsx`; test scan/chatbot (SSRF, rules, chatbot) đều pass trong 970 test.

## 16. Phase 3.4 — Đánh giá thao túng phiếu và biện pháp P0
| Tấn công | Chứng minh được? | Biện pháp | Còn lại |
|---|---|---|---|
| **Một người tự tạo nhiều “phiếu” cho một luật bằng cách bịa `variant`** (chuỗi `[a-z0-9-]{1,32}` tuỳ ý, mỗi biến thể là một dòng) | **Có** — trước khi sửa, test cho thấy một IP tạo được 60 dòng cho một luật/giờ, tự vượt `MIN_VOTES = 10` và biến mục đó thành “đủ mẫu” | **P0 đã làm:** mỗi người tối đa **5 biến thể/luật** (`MAX_VARIANTS_PER_RULE`); vượt → 429. Biến thể đã có vẫn đổi được phiếu. Không đổi giao diện: một báo cáo thật hiếm khi có > 5 biến thể của cùng luật | Một người vẫn tạo được tối đa 5 dòng/luật; cần ≥ 2 “người” để đạt ngưỡng 10 |
| **Replay / bấm đúp / gửi lại y hệt** | Có (khuếch đại ghi D1 không giới hạn nếu số dòng < 60) | **P0 đã làm:** gửi lại cùng nội dung → không ghi, không đổi `updated_at` (test) | Đổi qua lại giữa Có/Chưa vẫn ghi (là ý muốn của người dùng) |
| **Xoay IP / botnet / proxy** | Không chứng minh được trên production (cấm tạo phiếu giả) nhưng hiển nhiên về mặt thiết kế: không có CAPTCHA, mỗi IP mới là một “người” | Không có biện pháp P0 không ảnh hưởng UX/riêng tư. Phương án: Turnstile cho người ẩn danh (cần khoá site/secret trong cấu hình Cloudflare — **chủ repo quyết định**, tôi không tự thêm) | **Rủi ro chấp nhận có điều kiện:** dashboard chỉ mang tính tham khảo; không dùng phiếu để tự động đổi nội dung |
| **IP dùng chung (CGNAT, văn phòng)** | Có (test “Hạn chế đã biết”) | Không thể sửa mà không thêm định danh (cookie dài hạn = thêm dữ liệu cá nhân) | Đếm thiếu; phiếu sau ghi đè phiếu trước |
| **Đổi giữa tài khoản và ẩn danh** | Có | Chấp nhận: 2 “người” | — |
| **Chưa giới hạn tổng số phiếu toàn cục/giờ** | Có về lý thuyết | Chưa làm (không có bằng chứng cần thiết khi 0 phiếu) | Giám sát số phiếu trong tuần đầu |
Kiểm tra lại: 959 test trong `src/lib` đạt sau thay đổi.

## 17. Phase 3.4 — Audit nội dung giải thích (độc lập, đối chiếu OWASP/MDN/RFC)
**Phương pháp:** một agent không biết kết luận của tôi đọc lại toàn bộ văn bản giải thích/tác động/lệnh sửa của **63 luật** (`explain.ts`, `explain-more.ts`, `analyst.ts`, `impact.ts`, `fixes.ts`, `remediation.ts`) và đối chiếu với OWASP, MDN, RFC (có tra web). Tôi **không tin nguyên văn**: mỗi mục được kiểm với mã nguồn; mục có thể kiểm bằng thực nghiệm thì kiểm. Số “39” trong yêu cầu không khớp: có 63 luật.

**Đã sửa (kèm test hồi quy `content-audit-regressions.test.ts`, 7 test):**
1. `privacy.referrer-policy`: bỏ khẳng định sai “thiếu header thì trình duyệt gửi địa chỉ đầy đủ cho website khác” (mặc định hiện đại là `strict-origin-when-cross-origin`); nay nói rõ trình duyệt mới chỉ gửi tên miền, trình duyệt cũ có thể gửi cả đường dẫn.
2. `tls.protocol-version`: lệnh kiểm tra cũ in “chấp nhận” cả khi bị từ chối. **Kiểm bằng thực nghiệm** (OpenSSL 3.5.2): lần bắt tay thất bại in `Cipher is (NONE)` và khớp `Cipher is`; chạy trên `example.com` còn cho kết luận sai ở TLS 1.0/1.1 (máy không hỗ trợ). Lệnh mới phân biệt *chấp nhận / từ chối / máy bạn không hỗ trợ*, đã chạy thử trên host thật (TLS 1.2, 1.3 → chấp nhận; 1.0, 1.1 → không hỗ trợ). Sửa cả lệnh “verify” trong `explain-more.ts`.
3. `adv.dmarc-deep`: tiêu đề nói “theo dõi → cách ly → từ chối” nhưng snippet nhảy thẳng `p=quarantine; pct=100; adkim=s; aspf=s` (có thể đẩy thư hợp lệ của tên miền con/bên thứ ba vào spam). Nay bắt đầu `p=none`, tăng dần, kèm cảnh báo về `adkim/aspf=s`.
4. CSP: snippet chính thức nay có cảnh báo “chỉ bật sau khi Report-Only sạch; Next.js cần nonce; sẽ chặn script/style nội tuyến và host khác”; Report-Only nói rõ cần `report-to/report-uri` mới thu được báo cáo.
5. `tls.certificate-lifetime`: bỏ “60–90 ngày” như chuẩn; nêu mức tối đa **200 ngày với chứng chỉ cấp từ 15/03/2026** (CA/B Forum SC-081v3). *Cần người có chuyên môn xác nhận lại nguồn gốc: agent dựa trên tổng hợp của nhà cung cấp, chưa đọc trang ballot của CA/B Forum.* Ngưỡng 398 ngày trong **luật** không đổi.
6. `tls.hsts`: không nói “chỉ lần đầu” nữa — thiếu HSTS thì mỗi lần vào qua `http://` đều hở; có HSTS thì chỉ lần ghé đầu còn hở (preload mới bịt).
7. `browser.mixed-content`: bỏ khẳng định “kẻ cùng mạng đổi script để chạy mã” (trình duyệt hiện đại chặn script/CSS qua HTTP); nói rõ tác hại thực là tính năng hỏng, ảnh/media có thể bị thay ở trình duyệt cũ.
8. Mức tuyên bố quá tay: `exposure.sitemap-xml` (luật chỉ báo khi **thiếu** file; không phải “lộ đường dẫn”), `adv.shared-cache-leak`, `adv.dom-xss-flow`, `adv.postmessage`, `adv.graphql-surface` (heuristic độ tin cậy thấp; nay ghi “có dấu hiệu / cần kiểm tra”), `tls.http2` (bỏ “thiếu cải tiến bảo mật”).
9. SPF: chú thích `# …` nằm trong dòng giá trị TXT (dán nguyên sẽ làm bản ghi hỏng) — đã tách ra; `exposure.robots-txt`: không còn khuyên thay cả file bằng “Allow: /” mà không cảnh báo mất các luật Disallow.

**Chưa áp dụng (còn mở, cần kiểm chứng nguồn hoặc thay đổi lớn hơn — KHÔNG tuyên bố đã xong):** CSP giá trị `RECOMMENDED.csp` trong `remediation.ts` (vẫn là chính sách chặt, nay đã có cảnh báo nhưng chưa có biến thể nonce); Trusted Types nên đi qua Report-Only; snippet cookie nginx/Apache áp cho mọi cookie; CORP `same-origin` → `same-site`; Permissions-Policy (mặc định iframe khác nguồn); SameSite mặc định theo trình duyệt; thứ tự triển khai HSTS (`max-age` tăng dần trước `includeSubDomains/preload`); verify GraphQL `__typename` không chứng minh đã tắt introspection; Django `ALLOWED_HOSTS` một host; minify xoá comment HTML; `security.txt` Expires; CAA và DNSSEC cần cảnh báo gia hạn/DS sai; `exposure.secrets` verify bằng chuỗi đã che; `config.http-methods` Express chặn PUT/PATCH/DELETE; `cache-policy` áp cho cả tài nguyên tĩnh; các mục LOW (header-consistency, www-consistency, charset, EC 224/256, `impact` chung cho redirect/email-auth/CORS). Các mục “UNSURE” của agent (hạ cấp TLS, chữ hoa/thường `proxy_cookie_flags`, danh sách cipher “Intermediate”, `Protocols h2` Apache, ngưỡng HSTS 180 ngày, mặc định SameSite) chưa được xác minh nên **không** sửa.

**Giới hạn:** audit này là rà soát nội dung bằng một người đọc độc lập (mô hình), **không thay thế** người nhóm C; không đo mức dễ hiểu của người dùng. Không sửa `secrets.ts`, mã thu thập hay giao diện.

## 15. Lưu ý về quy trình
Thư mục làm việc được dùng chung với một session khác. Nhánh cũ `phase-3.2-validation` có thêm commit tài liệu của họ (`94c33bd`); nhánh review `phase-3.2-release-ready` **không** chứa commit đó (xem §10). Lịch sử/tệp của session khác không bị sửa.
