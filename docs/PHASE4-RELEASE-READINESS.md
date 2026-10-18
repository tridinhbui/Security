# PHASE4-RELEASE-READINESS — Sẵn sàng phát hành và QA bảo mật cuối

Ngày: 2026-10-17 · Phạm vi: PR #1, #2, #3 của `tridinhbui/Security` · Trạng thái chung: **CHƯA SẴN SÀNG PHÁT HÀNH** (2 blocker P0, xem §6)

Quy ước: **PASS** = đã kiểm chứng bằng lệnh/test chạy thật trong phiên này · **FAIL** = kiểm chứng và không đạt · **BLOCKED** = không kiểm chứng được vì thiếu quyền/công cụ · **UNKNOWN** = không có dữ liệu để kết luận (không suy đoán).
Không merge, không deploy, không bật auto-merge. Production giữ nguyên.

## 1. Bảng phụ thuộc giữa các PR

| PR | Nhánh → base | Ahead `main` | Thay đổi | CI GitHub Actions `test` | Workers Builds | Ghi chú |
|---|---|---|---|---|---|---|
| [#1](https://github.com/tridinhbui/Security/pull/1) | `docs/production-verification-a1b6fa4` → `main` | 2 commit (`a3d19ac`, `7c98864`) | 1 file (+14): `docs/explanation-qa-report.md` | PASS | failure | Chỉ tài liệu. `7c98864` là bản **mới hơn** của báo cáo (thay `a3d19ac`) |
| [#2](https://github.com/tridinhbui/Security/pull/2) | `phase-3.2-release-ready` → `main` | 5 commit (`6d2db48`, `cd0f4f0`, `b81f08e`, `ca0e6b4`, `3b9201c`) | 22 file (+817/−41): vote API, admin giải thích, sửa nội dung, tài liệu | PASS | failure | Tiêu đề ghi “DO NOT MERGE before review”. **Code bảo mật (API bình chọn, băm IP, admin) chưa được review trong phiên này** |
| [#3](https://github.com/tridinhbui/Security/pull/3) | `security-content-audit` → `main` | 3 commit (`94c33bd`, `cfd5359`, `4e1a241`) | 23 file (+1313/−16) | PASS | failure | Xem chi tiết dưới đây: **phụ thuộc ngầm vào hai PR còn lại** |

Điểm gốc chung của cả ba: `main` = `a1b6fa4`.

### Quan hệ trùng lặp (bằng chứng: `git patch-id`, `git merge-tree`)

| Phát hiện | Bằng chứng |
|---|---|
| `cfd5359` (trong #3) **giống hệt** `6d2db48` (trong #2) về nội dung | cùng `patch-id` `06f50e1a4e11…`; khác hash vì khác commit cha |
| `94c33bd` (trong #3) **giống hệt** `a3d19ac` (trong #1) | cùng `patch-id` `c0eaa81988ed…` |
| Báo cáo QA trong #3 là bản **cũ**, bản trong #1 (`7c98864`) mới hơn | `git diff #1 #3 -- docs/explanation-qa-report.md` cho thấy #3 sẽ xoá phần bằng chứng production của #1 |
| #3 mang theo code Phase 3.2 chưa review (`cfd5359`) | Merge #3 vào `main` sẽ đưa vào `main` thay đổi `ClarityVote`, `MatMat`, `admin/giai-thich`, `explain-feedback` vốn thuộc phạm vi review của #2 |
| #2 đã tự sửa độc lập cùng lỗi nội dung với #3 | Referrer-Policy (mặc định hiện đại), hạn chứng chỉ 200 ngày |

### Mô phỏng merge (`git merge-tree --write-tree`, không ghi gì vào repo)

| Thứ tự | Kết quả |
|---|---|
| #1 vào `main` | sạch |
| #2 vào `main` | sạch |
| #3 vào `main` | sạch khi đứng một mình (nhưng kéo theo code #2 chưa review, xem trên) |
| #1 + #3 | **XUNG ĐỘT** `docs/explanation-qa-report.md` |
| #2 + #3 | **XUNG ĐỘT** 5 file: `docs/phase-3.2-report.md`, `explain-feedback-route.test.ts` (add/add), `explain.ts`, `explain-more.ts`, `impact.ts` |
| #1 + #2 | sạch |

### Kết luận về thứ tự merge an toàn

**#1 → #2 (sau review) → #3 xếp chồng lên #2.** Không merge #3 vào `main` ở trạng thái hiện tại.

Đã chuẩn bị (commit `b55999c`, nay đã push): cherry-pick riêng commit nội dung của #3 (`4e1a241`) lên đầu `phase-3.2-release-ready`, chỉ còn **1 commit** thuộc #3. Giải quyết 3 xung đột: `explain.ts` và `impact.ts` giữ văn bản của #2 (đã sửa cùng lỗi); `explain-more.ts` giữ bản của #3 cho `long-validity` (đủ hơn: sửa cả mục “Sửa đúng thì”). Kết quả trên nhánh xếp chồng: **45 file test, 1085 test PASS**, typecheck PASS, build PASS.

**Công việc song song phát hiện sau khi hoàn thành phân tích trên:** repo cục bộ có thêm nhánh `integration/release-candidate` (`d6a8a22`, do một phiên khác tạo, chạy trong worktree riêng, chưa có trên remote) gồm `a074815` (tích hợp #1), toàn bộ #2, `f7c2b71` (nội dung của #3 áp lại), `9440bce` (nút sao chép trên thiết bị cảm ứng) và `FINAL-RELEASE-READINESS.md`. Đây là lời giải khác cho cùng vấn đề xếp chồng. **Tôi chưa review nhánh này và không dựa vào nó**; nó không chứa các sửa nội dung Phase 4 của tôi (`77f132e`: CSP `isDev`, Vercel/Supabase, báo cáo này). Trước khi chọn một phương án, nên đối chiếu hai nhánh để không có hai nguồn sự thật.

**Đã thực hiện (được chủ repo cho phép):** `git push --force-with-lease` lên `security-content-audit` (đầu cũ `4e1a241` → `21fbace`) và `gh pr edit 3 --base phase-3.2-release-ready`. PR #3 nay: base `phase-3.2-release-ready`, 3 commit riêng (nội dung, Phase 4, ghi chú), 15 file (+1168/−6), mergeable. Đầu cũ `4e1a241` không còn trên remote. Nhánh cục bộ `phase-3.2-validation` (`cfd5359`, chưa push) là bản trùng của #2, có thể bỏ.

## 2. CI

| Mục | Kết quả | Bằng chứng |
|---|---|---|
| GitHub Actions job `test` (typecheck, vitest, build, dry-run deploy) | **PASS** trên mọi đầu PR (#1 `7c98864`, #2 `3b9201c`, #3 `4e1a241`) | `gh pr checks`, `gh run list`: toàn bộ lượt chạy `success`, 58–80 giây |
| Workers Builds (`security`) | **FAIL**, nguyên nhân gốc **UNKNOWN** | Xem dưới |
| Log của Cloudflare Builds | **BLOCKED** | Máy chủ công cụ Cloudflare Builds cần OAuth do chủ tài khoản cấp; check-run trên GitHub không có annotation và không có `output.text` |

Dữ kiện đã quan sát về Workers Builds (không kèm suy đoán nguyên nhân):

| Commit | Nội dung | Workers Builds |
|---|---|---|
| `e02e4cb` | sửa typecheck Worker | success |
| `f718cf0` | **chỉ tài liệu** (`docs/explanation-qa-report.md`) | **failure** |
| `7a0f33e`, `2ad1d3d` | thêm `/api/version`, sửa nội dung | không có check-run |
| `a1b6fa4` (= `main`) | bộ khảo sát người dùng | **failure** |
| `7c98864` (#1), `3b9201c` (#2), `4e1a241` (#3) | tài liệu / nội dung / nội dung | **failure** (cả ba) |

Điều chắc chắn: lỗi **không do PR #1–#3 gây ra**, vì đã xuất hiện trên `main` (`a1b6fa4`) và trên một commit chỉ chứa tài liệu (`f718cf0`, và PR #1). Điều **không** được kết luận: nguyên nhân (cấu hình build, quota, container, bước deploy…). Báo cáo trước đó ghi nhận phiên bản `a1b6fa4` vẫn đang được phục vụ, nghĩa là trạng thái check không phản ánh đúng việc deploy, nhưng điều đó cũng không chứng minh deploy tương lai sẽ thành công.

Cần chủ tài khoản: mở log Build ID của `4e1a241` (`63b4c1a5-9150-4de3-8c26-76be9407bc4e`) và của build thành công `e02e4cb`, so bước lỗi; hoặc cấp OAuth cho Cloudflare Builds để phiên sau đọc trực tiếp.

## 3. Định lượng tác động của đề xuất đổi mức nghiêm trọng và khung tiêu chuẩn

Công cụ: `scripts/scoring-impact.ts` (chỉ đọc). Công thức điểm: `100 − Σ (trọng số mức × hệ số độ tin cậy)`, trọng số critical 30 / high 15 / medium 7 / low 3 / info 0; hệ số tin cậy high 1 / medium 0.7 / low 0.4; điểm nhóm bị trừ ×1.5; trần 96; hạng A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60.

| Đề xuất | Phạt hiện tại → đề xuất | Điểm tổng | Điểm nhóm | Nhận xét |
|---|---|---|---|---|
| `exposure.source-maps` medium → low (tin cậy high) | 7 → 3 | **+4** | +6 (Exposure) | Báo cáo demo: **69 (D) → 73 (C)**, tức đổi hạng chữ cái của website mẫu đang hiển thị cho người dùng. Với điểm gốc phân bố đều 0–96, khoảng **16%** điểm gốc đổi hạng |
| `adv.dom-xss-flow` medium → low (tin cậy low) | 2.8 → 1.2 | **+1.6** | +2.4 (Browser) | ~8% điểm gốc đổi hạng. Demo không có phát hiện này |
| Cả hai | — | +5.6 | — | ~25% điểm gốc đổi hạng; site sạch bị trần 96 hấp thụ một phần |

Không có test nào ghim `adv.dom-xss-flow` ở mức medium. Chỉ `engine.test.ts:76` ghim `exposure.source-maps` là medium. **Chưa có tập dữ liệu quét thật** để biết tần suất hai phát hiện này trên website thật (UNKNOWN); benchmark nội bộ (`benchmark.test.ts`) không có website mang đúng hai lỗi này, nên không thể đo precision/recall của việc đổi mức.

**Đề xuất (chưa làm):** không đổi trực tiếp bằng một nhãn. Với `source-maps`: hạ về `low` mặc định; chỉ giữ `medium` khi bản đồ chứa `sourcesContent` có khớp mẫu bí mật/địa chỉ nội bộ. Đó là thay đổi **logic phát hiện**, cần test độc lập (website có map sạch / map chứa khoá giả) và ghi nhận trước/sau của benchmark. Giữ `dom-xss-flow` ở mức hiện tại cho tới khi có dữ liệu thật, vì giải thích đã gắn nhãn “tiềm năng” và điểm đã được nhân hệ số tin cậy thấp.

**OWASP Top 10 / ASVS:** khung tham chiếu chỉ ảnh hưởng **hiển thị** (bảng độ phủ, nhãn trong báo cáo), **không** ảnh hưởng điểm số: `calculateScore` chỉ dùng mức nghiêm trọng và độ tin cậy. Hiện 51/63 luật có ánh xạ OWASP 2021 (A05: 23, A02: 15, A07: 6, A01/A03/A04/A08: 3, A06: 1). Chuyển sang Top 10:2025 đổi số hiệu A02↔A04, A03↔A05, A05→A02, A06→A03 (Software Supply Chain Failures), SSRF gộp vào A01, thêm A10 (Mishandling of Exceptional Conditions); cần bảng ánh xạ do người có chuyên môn duyệt, không phải đổi tên hàng loạt. ASVS 5.0 đánh số lại yêu cầu; phải xác nhận ngày phát hành và mã ở trang chính thức trước khi viết ánh xạ (nguồn tôi tìm được chỉ là thứ cấp).

## 4. Xác thực snippet

Dự án tối thiểu dựng trong thư mục tạm, lấy snippet **trực tiếp** từ `DEEP_DIVE` (không chép tay), chạy thật:

| Nền tảng | Kết quả | Chi tiết |
|---|---|---|
| Next.js 16.3.8 (`next build` + `next start`) | **PASS** | Snippet `proxy.ts` (CSP nonce), `next.config.ts` (HSTS, nosniff, Referrer-Policy, Permissions-Policy, X-Frame-Options, `poweredByHeader:false`), route CORS, route cookie đều biên dịch và qua kiểm kiểu. Phản hồi thật: header đúng; CSP có nonce mới mỗi request và **không** có `'unsafe-eval'` ở production; origin lạ **không** nhận `Access-Control-Allow-Origin`, origin trong danh sách nhận đúng origin đó; cookie `Secure; HttpOnly; SameSite=lax`; không có `X-Powered-By`; build mặc định không sinh `.map`. Trên trình duyệt thật: trang `hello` hiển thị, 8/8 script mang nonce, không có vi phạm CSP trong console |
| Cloudflare Workers (`wrangler dev --local`, workerd cục bộ) | **PASS (cục bộ)** | `public/_headers` áp lên tài nguyên tĩnh; snippet Worker đặt được HSTS; snippet CORS đúng. Xác nhận bằng thực nghiệm: phản hồi do mã Worker tạo ra **không** nhận header từ `_headers` (đúng như đã ghi trong nội dung) |
| Supabase RLS (SQL) | **PASS một phần** | Chạy trên PostgreSQL thật qua PGlite, **mô phỏng** vai trò `anon`/`authenticated` và `auth.uid()`. Kết quả: truy vấn kiểm tra liệt kê đúng bảng thiếu RLS trước khi áp; sau khi áp: `anon` không thấy dòng nào, người dùng A chỉ thấy dòng của mình, chèn dòng thuộc người khác bị từ chối, sửa dòng của người khác ảnh hưởng 0 dòng. **Không phải Supabase thật** (PostgREST, JWT thật, schema `auth` thật) |
| Vercel `vercel.json` | **PASS cú pháp / BLOCKED chạy thật** | 7 snippet JSON đều hợp lệ và đúng dạng `headers[].source/headers[].key/value`. Chưa chạy: không có Vercel CLI hay đăng nhập |
| Nginx | **BLOCKED** | Không có `nginx` trong môi trường, không `nginx -t` |
| Thao tác trên bảng điều khiển Cloudflare/Supabase (Always Use HTTPS, Minimum TLS, API Keys…) | **BLOCKED** | Cần giao diện/quyền tài khoản; chỉ đối chiếu với tài liệu |
| Triển khai thật lên Cloudflare/Vercel/Supabase | **BLOCKED** | Theo yêu cầu không deploy |
| `next dev` với CSP có `isDev` | **KHÔNG kiểm** | Chỉ kiểm production; phần dev dựa trên tài liệu Next.js đi kèm repo |

Sai sót nội dung phát hiện khi đối chiếu, **đã sửa** trong `deep-dive.ts`: (1) thiếu `'unsafe-eval'` cho dev trong mẫu CSP Next.js (thêm điều kiện `isDev` + mục “lỗi thường gặp”); (2) “Vercel đã tắt TLS 1.0/1.1” là khẳng định chưa kiểm chứng, thay bằng nội dung theo tài liệu Vercel (chỉ TLS 1.2/1.3; chuyển HTTP→HTTPS bằng 308); (3) Supabase có khoá mới `sb_publishable_…`/`sb_secret_…`, bỏ chỉ dẫn menu cụ thể có thể lỗi thời.

## 5. Content QA

| Hạng mục | Kết quả |
|---|---|
| 63/63 luật có tiêu đề dễ hiểu, hình dung, tác động, mẫu giải thích riêng, khoá tiêu chuẩn | **PASS** (`deep-dive.test.ts` + `explain-quality.test.ts`) |
| 25 tầng đào sâu: cấu trúc, ≥ 2 nguồn, lệnh kiểm chứng chỉ đọc, không cụm “an toàn tuyệt đối” | **PASS** (test) |
| Cấu hình header mẫu không tạo phát hiện lỗi mới khi chạy qua toàn bộ luật | **PASS** (test) |
| 59 URL nguồn trong tầng đào sâu | **PASS** (cả 59 trả HTTP 200; chỉ kiểm sự tồn tại, **không** kiểm nội dung khớp) |
| Độ chính xác của từng khẳng định kỹ thuật | **PASS có điều kiện**: đã đối chiếu tài liệu cho CSP/Next.js, Vercel, Supabase, Workers `_headers`, hạn chứng chỉ, mặc định Referrer-Policy. Chưa đối chiếu độc lập từng câu còn lại với tài liệu gốc; còn dựa vào kiến thức chuẩn (RFC 6797, 8996, 7208, 9111, MDN). **Theo dõi:** RFC 7489 (DMARC) có thể được thay thế bởi bản mới; chưa kiểm tra |
| Phát hiện từ #2 (nội dung) | Đã đọc phần khác biệt nội dung của #2 (analyst/fixes/impact/explain): sửa đúng hướng (SSL stripping không còn nói “lần đầu” tuyệt đối, sitemap không còn là lỗi bảo mật, GraphQL chỉ là “tham chiếu endpoint”, kiểm tra TLS cũ xử lý “no protocols available”). Chưa review code API/DB của #2 |

## 6. Phát hiện P0 / P1 / P2

### P0 (chặn phát hành)

| # | Phát hiện | Bằng chứng | Cần làm |
|---|---|---|---|
| P0-1 | **Workers Builds failure, nguyên nhân UNKNOWN**; xuất hiện trên `main`, trên commit chỉ-tài-liệu và trên cả ba PR | §2 | Chủ tài khoản đọc log hoặc cấp OAuth. Giữ nguyên production tới khi rõ nguyên nhân và có một build thành công |
| P0-2 (ĐÃ XỬ LÝ) | **PR #3 trước đó không merge được an toàn**: chứa code #2 chưa review (`cfd5359`), kèm báo cáo QA cũ làm xung đột #1, xung đột 5 file với #2 | §1 | Đã đẩy nhánh xếp chồng và đổi base (xem §1) |
| P0-3 (cổng review) | **PR #2 chưa được review code bảo mật** (API bình chọn, băm IP, admin). Tiêu đề PR cũng ghi “DO NOT MERGE before review” | §1 | Review có người chịu trách nhiệm trước khi merge; #3 chỉ nên vào sau #2 |

### P1

| # | Phát hiện | Bằng chứng | Đề xuất |
|---|---|---|---|
| P1-1 | **Lỗ hổng phát hiện (âm tính giả): khoá bí mật kiểu mới của Supabase `sb_secret_…` không được `exposure.secrets` nhận ra** | `grep sb_secret` trong `src/lib/scanner` không có kết quả; `secrets.ts` chỉ nhận `service_role` dạng JWT. Tài liệu Supabase nêu khoá mới có tiền tố `sb_secret_` | Thêm bộ phát hiện `sb_secret_` (critical) và ghi nhận `sb_publishable_` là công khai theo thiết kế, **kèm test độc lập**. Cần xác nhận độ dài/định dạng chính xác ở tài liệu Supabase trước khi viết regex. Không sửa trong đợt này vì là thay đổi logic phát hiện |
| P1-2 | OWASP Top 10:2021 và ASVS 4.0.3 đã bị thay thế | §3, audit O1/O2 | Lập bảng ánh xạ được duyệt; không ảnh hưởng điểm số |
| P1-3 | Snippet chưa chạy thật trên Vercel, Nginx, Supabase thật, bảng điều khiển Cloudflare | §4 | Kiểm trên môi trường staging có quyền |

### P2

| # | Phát hiện | Đề xuất |
|---|---|---|
| P2-1 | `exposure.source-maps` (medium) có thể lạm phát; đổi sẽ nâng demo từ D lên C | §3: chỉ đổi cùng thay đổi logic và test độc lập |
| P2-2 | `adv.dom-xss-flow` medium với độ tin cậy thấp | Chờ dữ liệu quét thật |
| P2-3 | Neo `#wstg-…` không dẫn tới đúng bài kiểm tra | Dùng URL riêng của từng bài |
| P2-4 | 10 luật không có trong `OWASP_MAP` chưa được ghi lý do | Chú thích |
| P2-5 | Tầng đào sâu mới phủ 25/63 luật | `REMEDIATION-CONTENT-ROADMAP.md` |

## 7. Hồi quy cuối (nhánh xếp chồng trên #2 + công việc Phase 4)

| Hạng mục | Kết quả |
|---|---|
| `npm test` | **PASS**: 45 file, 1085 test |
| `npm run typecheck` | **PASS** (exit 0) |
| `npm run build` (OpenNext) | **PASS** |
| UI `/demo`, chế độ Dễ hiểu ↔ Kỹ thuật | **PASS**: chuyển chế độ đúng, khối “Đào sâu kỹ thuật” có mặt ở cả hai chế độ (thu gọn mặc định), không có lỗi console |
| **Logic phát hiện không đổi** | **PASS**: so sánh vi phân `(luật, trạng thái, mức, độ tin cậy, fingerprint)` + điểm + hạng của **toàn bộ luật** trên **40 biến thể cấu hình** (bỏ từng header, giá trị lạ của HSTS/CSP/CORS/cookie/Referrer/…) giữa `phase-3.2-release-ready` (#2) và nhánh Phase 4: **giống hệt từng dòng (1880 dòng)** |
| Production | Không chạm: không deploy, không bật auto-merge |

Giới hạn: so sánh vi phân dùng bộ cấu hình của fixtures; không phải toàn bộ Internet. Chưa chạy quét thật qua mạng hay container.

## 8. Kế hoạch merge đề xuất (mỗi bước cần bạn đồng ý, không bước nào tự động)

1. **Gỡ P0-1**: đọc log Workers Builds (build `63b4c1a5-…` và `e02e4cb`), sửa nguyên nhân hoặc ghi nhận chính thức là check không đáng tin. Không merge gì vào `main` trước khi biết một lần merge sẽ tạo bản dựng thế nào, vì mỗi commit trên `main` kích hoạt Workers Builds và đổi `/api/version`.
2. **P0-2 đã xử lý**: nhánh xếp chồng đã push, base PR #3 là `phase-3.2-release-ready`.
3. **Merge #1** (chỉ tài liệu, độc lập, đã sạch) khi P0-1 đã được hiểu. Nếu muốn tránh một bản dựng không cần thiết, gộp #1 vào cùng đợt với #2.
4. **Review #2** (P0-3), sửa theo review, merge `main`. GitHub sẽ tự đổi base của PR xếp chồng.
5. **Merge #3** (đã xếp chồng, 1 commit). Chạy lại `npm test`, typecheck, build trên kết quả sau cùng.
6. **Sau merge**, không deploy thủ công: dùng quy trình `/api/version` đã nêu trong `phase-3.2-report.md` (so `commit` và `workerVersionId` với `main` và tab Deployments).
7. **Tách việc**: P1-1 (phát hiện `sb_secret_`) làm thành PR riêng có test độc lập; P1-2/P2-1 chỉ làm khi đã có bảng ánh xạ và số liệu benchmark trước/sau.
