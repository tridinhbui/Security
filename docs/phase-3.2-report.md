# Báo cáo Phase 3.2 — Kiểm chứng người dùng thật và hệ thống phản hồi

**Trạng thái: CHƯA HOÀN TẤT — chờ buổi thử nghiệm với người thật.** Phần kỹ thuật đã xác minh; phần cần người tham gia (mục 4–8 của yêu cầu) **chưa thực hiện** và **không có số liệu nào được bịa**.

Thời điểm lập: `2026-10-17T20:38:14Z`. Nhánh: `phase-3.2-validation` (chưa đẩy lên `main`, chưa deploy).

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
5. Bundle Worker nén **3,39 MB**, lớn hơn mốc 3 MB của gói Free (gói Paid cho phép lớn hơn). Cần theo dõi nếu thêm tính năng.

## 8. CI (cục bộ, trước khi xin phê duyệt)
- `npm run typecheck` (cả hai tsconfig): sạch.
- `npx vitest run`: **964 passed (964)**.
- `npm run build` (OpenNext) + `wrangler deploy --dry-run`: thành công, không lỗi.
- Chưa deploy. Nhánh chưa được đẩy lên `main`.

## 9. Lưu ý về quy trình
Nhánh `phase-3.2-validation` dùng chung thư mục làm việc với một phiên khác nên có **một commit tài liệu không phải của đợt này** (`94c33bd`, ghi nhận kết quả `/api/version`). Nó chỉ sửa `docs/explanation-qa-report.md`.
