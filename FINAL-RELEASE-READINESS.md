# VibeSec — Final Release Readiness

Cập nhật: 2026-10-17 (Phase 3.5, tích hợp). **Quyết định hiện tại: NO-GO production.** Không có PR nào được merge, không deploy, không ghi D1 production, không đổi cấu hình Cloudflare.

> **Quan trọng:** đẩy lên `main` **tự động deploy** qua Workers Builds (đã quan sát: `/api/version` đổi theo mỗi commit). Vì vậy **merge = deploy**, kể cả PR chỉ có tài liệu. Mọi điều kiện “trước khi deploy” dưới đây cũng là điều kiện trước khi merge.

## 1. Trạng thái từng PR (đo ngày 2026-10-17)

| PR | Nội dung | Draft | CI `test` | Workers Builds | Phân loại | Ghi chú |
|---|---|---|---|---|---|---|
| [#1](https://github.com/tridinhbui/Security/pull/1) `docs/production-verification-a1b6fa4` (`7c98864`) | 1 tệp tài liệu (xác minh production `a1b6fa4`) | có | xanh | failure | **MERGE READY** (chỉ tài liệu) | Chỉ trùng tệp với #3 (`docs/explanation-qa-report.md`) — xử lý bằng thứ tự merge bên dưới. Merge vẫn kích hoạt một lần deploy. |
| [#2](https://github.com/tridinhbui/Security/pull/2) `phase-3.2-release-ready` (`3b9201c`) | Bình chọn: hardening, test, UX, tài liệu thử nghiệm, báo cáo Phase 3.2 | có | xanh | failure | **MERGE READY về mã · BLOCKED về release** | Mã đã qua review, 979 test. Bị chặn bởi các điều kiện §5 (không phải do mã). |
| [#3](https://github.com/tridinhbui/Security/pull/3) `security-content-audit` (`4e1a241`) | Sửa 3 lỗi sự thật + “Đào sâu kỹ thuật” cho 26 luật + test | **không** | xanh | failure | **FIX REQUIRED** (cấu trúc nhánh) | Nhánh dựng trên `phase-3.2-validation` nên mang theo bản cũ của commit Phase 3.2 (`cfd5359`) và `94c33bd` (trùng #2/#1), **thiếu** các sửa của #2 từ Phase 3.3–3.4 (lỗi IPv4-mapped IPv6, trần 5 biến thể, idempotency). Nội dung chính (`4e1a241`) tốt và đã được tích hợp sạch — xem §3. Không sửa nhánh của session khác. |

Tổ tiên (đã kiểm): cả ba nhánh đều tách từ `a1b6fa4` (= `origin/main`). #2 = `a1b6fa4`+5 commit; #1 = `a1b6fa4`+2; #3 = `a1b6fa4`+3 (`94c33bd`, `cfd5359`, `4e1a241`). Trùng lặp: `cfd5359` ≡ `6d2db48` của #2 (cùng nội dung, khác SHA); `94c33bd` ≈ `a3d19ac` của #1.

## 2. Thứ tự merge an toàn (đề xuất — chưa thực hiện)
Không merge #3 trước #2 (xung đột 12 tệp, và sẽ ghi đè các sửa bảo mật). Thứ tự:

1. **#1** (tài liệu) — không xung đột.
2. **#2** — sau #1, không xung đột (không trùng tệp).
3. **#3 sau khi rebase**: chỉ giữ commit `4e1a241`, đặt lên trên #2. Nhánh `integration/release-candidate` (đã đẩy, KHÔNG phải PR vào `main`) là bản đã làm sẵn việc này: `#2` + merge `#1` + `4e1a241` (giải quyết 3 xung đột nội dung) + 1 sửa nhỏ. Chủ #3 có thể `git rebase --onto origin/main 94c33bd`/cherry-pick `4e1a241` hoặc dùng nhánh tích hợp.
4. Mỗi lần merge là một lần deploy: dừng và kiểm `/api/version` sau từng bước, hoặc gom thành **một** PR tích hợp để chỉ deploy một lần (khuyến nghị: duyệt `integration/release-candidate` thành một PR duy nhất thay cho #2+#3, đóng #1 hoặc để merge riêng).

## 3. Kết quả tích hợp (`integration/release-candidate`)
- **Xung đột khi cherry-pick `4e1a241` lên #2: 3 tệp** (`explain.ts`, `explain-more.ts`, `impact.ts`) — cả hai bên cùng sửa Referrer-Policy, hạn chứng chỉ và `adv.shared-cache-leak`. Giải quyết: lấy bản của #3 cho Referrer-Policy và hạn chứng chỉ (đủ lộ trình 398 → 200 → 100 → 47 ngày, chính xác hơn), giữ bản của #2 cho `adv.shared-cache-leak` (#3 để nguyên câu quá lời “bất cứ lúc nào”). **Hai audit độc lập cùng kết luận giống nhau** về Referrer-Policy và hạn chứng chỉ → tăng độ tin cậy.
- Trùng lặp nội dung giữa #2 §17 và #3: Referrer-Policy, hạn chứng chỉ, nonce Next.js — **không sửa lại**. Phần #2 đã sửa mà #3 chưa đụng (lệnh TLS, DMARC, CSP cảnh báo, HSTS, mixed content, SPF, robots, các heuristic độ tin cậy thấp) và phần #3 thêm (tầng Deep Dive 26 luật) không chồng nhau.
- Phần còn mở của audit (xem `docs/phase-3.2-report.md` §17: cookie nginx/Apache, CORP, `security.txt`, CAA/DNSSEC, `ALLOWED_HOSTS`, minifier comment HTML…) **chưa được #3 xử lý** — vẫn mở.
- Sửa thật phát hiện khi tích hợp (1): `DeepDiveView` ẩn nút Sao chép đến khi di chuột nên **không dùng được trên điện thoại** → hiện luôn dưới `sm` (xác nhận trong trình duyệt 375px: opacity 1). Cùng mẫu đó còn ở `Report.tsx:422` (có sẵn trên `main`, không do #2/#3) — **chưa sửa, ghi nhận**.

## 4. Bằng chứng kiểm tra (trên worktree tích hợp riêng, sau khi giải xung đột)
| Kiểm tra | Kết quả |
|---|---|
| `npm run typecheck` (2 tsconfig) | sạch |
| `npx vitest run` | **45 file / 1085 test pass · 0 fail · 0 skip** |
| `npm run build` (OpenNext) | thành công |
| Docker `wrangler deploy --dry-run` | thành công: image container dựng được, binding hợp lệ; `Total Upload 14636 KiB / gzip 3420 KiB` (giới hạn hiện hành 64 MiB chưa nén, không còn giới hạn nén) |
| Trình duyệt, mobile 375px `/demo` | không tràn ngang; nút bình chọn 40px; textarea chatbot 42→116→166px; “Đào sâu kỹ thuật” mở được, khối mã cuộn trong khung, 7 mục đủ, nút Sao chép hiện |
| Trình duyệt, desktop 1280px `/demo` | không tràn ngang; nút bình chọn 32px; textarea 42→116→166px |
| Chưa kiểm | admin `/admin/giai-thich` bằng tài khoản thật; thiết bị thật; dark mode của `DeepDiveView` (dùng `bg-white`) |

### Review bảo mật PR #2 (bằng chứng: `src/lib/__tests__/explain-feedback-route.test.ts`, 25 test route + test DB)
| Hạng mục | Kết quả |
|---|---|
| CSRF | thiếu/lệch/gần giống Origin → 403, không ghi |
| Lạm dụng bình chọn | trần 60 phiếu/giờ/người → 429; **tối đa 5 biến thể/luật/người** (chứng minh: trước đó 1 IP tự tạo 60 dòng cho một luật và vượt `MIN_VOTES`) |
| Idempotency | gửi lại y hệt → không ghi, `updated_at` không đổi |
| IPv6 | gom `/64`; IPv4 nhúng trong IPv6 (`::ffff:a.b.c.d`) **không** bị gộp (lỗi do PR này đưa vào ở bản đầu, đã sửa + test) |
| Riêng tư | không IP/tên miền/URL ở cột nào; nhận xét bị che trước khi lưu |
| Còn lại, KHÔNG xử lý được bằng mã | IP xoay vòng/botnet (không CAPTCHA); IP dùng chung đếm thiếu → dashboard chỉ tham khảo |

## 5. Phân tích quy định TLS (nguồn gốc) và tác động scoring
- **Nguồn:** CA/Browser Forum Baseline Requirements, ballot **SC-081v3** (đã đọc bảng §6.3.2 trong thay đổi đã merge của `cabforum/servercert` PR #553): tối đa **398 ngày** trước 15/03/2026 → **200 ngày** (15/03/2026–14/03/2027) → **100 ngày** (từ 15/03/2027) → **47 ngày** (từ 15/03/2029). Áp dụng cho chứng chỉ **cấp** từ mỗi mốc. (Let’s Encrypt tự công bố lộ trình 64 ngày từ 10/02/2027 — nguồn thứ cấp, không dùng làm căn cứ ở đây.) Trình duyệt thực thi qua chính sách root store, không phải mọi trình duyệt như nhau.
- **Tác động scoring của #2/#3 hiện tại: KHÔNG.** `4e1a241` chỉ đổi chuỗi văn bản (`summary`/`explanation` trong `transport.ts` và nhãn trong `advanced.ts`); ngưỡng phát hiện vẫn `> 398`, mức nghiêm trọng, độ tin cậy, dấu vân tay không đổi. Chứng minh: toàn bộ test benchmark/score/fingerprint pass; diff luật chỉ chạm chuỗi. `ENGINE_VERSION` không cần tăng.
- **Không đổi ngưỡng sang 200 (cố ý).** Chứng chỉ cấp **trước** 15/03/2026 vẫn hợp lệ tới 398 ngày (còn hiệu lực đến ~4/2027); hạ ngưỡng sẽ tạo dương tính giả hàng loạt. Cải tiến đúng nếu muốn: chỉ báo >200 ngày khi `notBefore ≥ 2026-03-15` — nhưng CA tuân thủ không cấp loại đó nên chỉ bắt được CA riêng/sai; giá trị thấp. Nếu làm sau này **phải** có impact analysis trên benchmark (27 site) + test mới và tăng `ENGINE_VERSION`.
- Mức nghiêm trọng khác (HSTS, CSP, cookie…): không đổi trong các PR này.

## 6. Workers Builds failure — BLOCKED
- Bằng chứng thu được (chỉ đọc): check “Workers Builds: security” **failure ở mọi commit từ `f718cf0`** (trên `main`) và ở cả ba PR (#1 `7c98864`, #2 `3b9201c`, #3 `4e1a241`); thành công đến `e02e4cb`. `f718cf0` chỉ sửa tài liệu → không do mã. Ở `main`, phiên bản Worker vẫn được tải lên và triển khai 100% trước khi check kết thúc (`c101a829…`, `6311c79b…`); ở nhánh PR **không có phiên bản mới nào** được tải lên (phiên bản mới nhất vẫn `6311c79b…`). `/api/version` = `a1b6fa4` khớp. Check không có annotation/ nhật ký.
- Đã thử: GitHub API (check-runs), `wrangler versions/deployments list`, kiểm cấu hình bằng dry-run Docker (hợp lệ). **Không có quyền đọc nhật ký bản dựng** (công cụ Cloudflare Builds chưa uỷ quyền; `wrangler` không có lệnh log). Không đoán, không đổi cấu hình.
- **Cần từ chủ tài khoản Cloudflare** (đúng những thứ này, che secret): Dashboard → Workers & Pages → `security` → Builds/Deployments → mở Build ID **`f0943bfb-6eb4-42c4-af5e-6016849e43be`** (#2), **`79927e71-bbb5-4c00-af46-d89a4543cdd0`** (a1b6fa4) và một build `success` của `e02e4cb`: (1) tên bước đỏ, (2) ~20 dòng log quanh lỗi, (3) *Build command*, *Deploy command*, *Root directory*, *Branch control* (có bật build cho nhánh không phải production không), (4) các biến môi trường build (tên, không giá trị). Hoặc uỷ quyền MCP “Cloudflare Builds” cho session.

## 7. Điều kiện bắt buộc trước merge/deploy (chưa đạt)
- [ ] **Workers Builds**: đọc log và biết nguyên nhân (§6). Chưa → NO-GO.
- [ ] **Admin QA bằng tài khoản thật** theo `docs/admin-qa-checklist.md` (chủ repo).
- [ ] **Expert security review** các giải thích đã sửa/viết lại, dùng `docs/user-testing/security-reviewer-sheet.md` (≥ 1 người nhóm C). Cần xác nhận riêng §17 của `docs/phase-3.2-report.md` và 26 mục Deep Dive.
- [ ] **User testing 3–5 người** theo `docs/user-testing/` (≥ 3 nhóm A, ≥ 1 nhóm C); điều kiện “đủ để quyết định” ở README §8. **Hiện 0 người, 0 phiếu** — không có xếp hạng, không có kết luận về độ dễ hiểu.
- [ ] Quyết định rủi ro bình chọn (§4): chấp nhận hay thêm Turnstile.
- [ ] Chủ #3 quyết định cách đưa `4e1a241` vào (rebase hoặc dùng nhánh tích hợp); #3 hiện không phải Draft.
- [ ] Sau khi merge/deploy: `curl /api/version` khớp commit; đọc `workerVersionId` trên tab Deployments.

## 8. Kết luận
| Hạng mục | Quyết định |
|---|---|
| Kỹ thuật (mã, test, build, dry-run, UI) | **Đạt** trên nhánh tích hợp |
| Release | **NO-GO** — Workers Builds chưa có nguyên nhân; chưa có admin QA, expert review, user testing |
