# Xác minh sau deploy — PR #5 (production `fdca0a3`, bộ luật v11)

Ngày 2026-10-18. Production: `https://security.tridinhbui0901.workers.dev`, `/api/version` → commit `fdca0a3…`, `workerVersionId e6c27b44-…`.

**Mục tiêu quét thật được phép:** chỉ các website dựng sẵn để kiểm thử công khai `*.badssl.com` (mục đích của chúng là để công cụ kiểm thử bảo mật thử nghiệm) và website của chính VibeSec. Không quét website bên thứ ba khác. Quét nhanh là thụ động (≤ 14 request).

## Kết quả

| # | Hạng mục | Kết quả | Bằng chứng |
|---|---|---|---|
| 1 | Quét thật trên production: `badssl.com`, `http.badssl.com`, `expired.badssl.com` | **FAIL → đã sửa** (nhánh `fix/post-deploy-verification`, chưa deploy) | Lỗi **P0** dưới đây |
| 1a | `badssl.com` (thiếu header, không DNS email) | PASS | 69/D, phạm vi 6/7 (chứng chỉ: chỉ có ở quét đầy đủ), 2 cần sửa (CSP, HSTS), 10 nên cải thiện; cookie: không áp dụng |
| 1b | `http.badssl.com` (cố ý chỉ HTTP, HTTPS chuyển xuống HTTP) | PASS | 55/F; báo đúng “HTTP không chuyển sang HTTPS” và “chuyển hướng hạ cấp HTTPS→HTTP” |
| 1c | **`expired.badssl.com` (chứng chỉ hết hạn)** | **FAIL (P0)** | Production báo **“HTTPS hoạt động và chứng chỉ được tin cậy”**, 76/C, bằng chứng `TLS: ?, nhà cấp: ?`; recon cho thấy trang chủ là `526` với `server: cloudflare` |
| 1d | Engine quét đầy đủ (63 luật, Node, mạng thật) trên badssl.com, expired / self-signed / wrong.host / http.badssl.com, VibeSec | PASS | Cả 63 luật chạy; chứng chỉ hết hạn / tự ký / sai tên miền đều “Chứng chỉ HTTPS không được tin cậy” (Cao); mọi phát hiện chưa đạt có giải thích riêng + bước sửa + lệnh kiểm tra lại (0 thiếu); tên miền không tồn tại → `dns_failed` (không chấm điểm) |
| 2 | Trần quét nhanh 89 | PASS | Mọi kết quả production có `ceiling: 89`; không kết quả nào hạng A |
| 2 | Ranh giới hạng | PASS | 69→D, 76→C, 55→F khớp `gradeFor` (A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60) + unit test |
| 2 | Cache v11 | PASS | Lần đầu `cached: false`; quét lại `https://badssl.com/some/path?x=1` → `cached: true`, cùng 69/D, `ceiling 89` (cache theo tên miền + phiên bản bộ luật) |
| 3 | URL không hợp lệ (rỗng, `javascript:`, `127.0.0.1`, `[::1]`, `169.254.169.254`, `localhost`, `ftp://`, `user:pw@`, cổng 8443, số, không phải JSON, 3000 ký tự) | PASS | Tất cả 400 với mã lỗi và câu tiếng Việt cụ thể; không request nào ra ngoài |
| 3 | Thiếu / sai Origin | PASS | 403 `forbidden` |
| 3 | Giới hạn tốc độ | PASS | Sau 3 lượt quét thật + 7 lượt thăm dò địa chỉ nội bộ (theo thiết kế, thăm dò nội bộ cũng tính vào hạn mức) → 429 kèm hướng dẫn. Hệ quả: production không cho IP kiểm thử quét thêm trong 1 giờ |
| 3 | DNS không tồn tại / không kết nối được / chuyển hướng / kết quả một phần | PASS (engine thật + test) | `dns_failed`; không kết nối được → “chưa quét được” (test); chuyển hướng hạ cấp được báo (1b); kết quả một phần → phạm vi “chưa đầy đủ” + trần 89 (expired.badssl.com qua engine: 5/7 nhóm) |
| 3 | Timeout | PASS (test) | Ngân sách 14 request / 12 giây và DoH 4 giây có test; không tạo timeout thật trên production |
| 4 | Quyền truy cập khi chưa đăng nhập | PASS | `/api/scans*`, share, help-requests, project-scans, chat, feedback, github/repos → 401; `/api/admin/*` → 401/404; `/admin*` → 404; `/dashboard` hiện màn hình đăng nhập |
| 4 | Rò rỉ dữ liệu | PASS | `/api/version` chỉ 4 trường; JSON quét nhanh không có giá trị cookie (chỉ tên + cờ); source map `/_next/static/*.js.map` → 404; API có `Cache-Control: no-store`; header bảo mật đầy đủ |
| 4 | Link chia sẻ sai | Lưu ý (P3) | `/r/<token sai>` hiện “Không tìm thấy” kèm `noindex` nhưng mã HTTP 200 (Next.js đã bắt đầu stream vì có `loading.tsx`). Không lộ dữ liệu |
| 4 | Cô lập dữ liệu giữa tài khoản | BLOCKED trên production | Cần hai tài khoản thật (không được tạo tài khoản); đã có test đơn vị kiểm quyền sở hữu trong `repo.test.ts` |
| 5 | Nguyên nhân chính xác lỗi Workers Builds trên nhánh PR | **BLOCKED** | Log chỉ có trong Cloudflare dashboard; công cụ Cloudflare Builds cần OAuth (chủ tài khoản bật qua `/mcp`). Giả thuyết và cách xử lý: `VIBESEC_CONTENT_USABILITY_SECURITY_AUDIT.md` §12.5 |
| 6 | Mobile 375px trên production | PASS | 0 vùng cuộn lồng nhau, 0 phần tử tràn ngang; điểm 69/D, phạm vi “6/7 nhóm · chưa đầy đủ nên không xếp hạng A” hiển thị ngay dưới điểm, đếm 2 cần sửa / 10 nên cải thiện / 18 đạt khớp danh sách |

## Lỗi P0 đã sửa (chưa deploy)

**Triệu chứng.** Trên production, website có chứng chỉ hết hạn (`expired.badssl.com`) được báo “HTTPS hoạt động và chứng chỉ được tin cậy”, ra 76/C. Các mục header khác được chấm trên **trang lỗi của Cloudflare**, không phải trang của website.

**Nguyên nhân gốc.**
- Quét nhanh và quét lai chạy trong Worker. Khi chứng chỉ máy chủ không hợp lệ, `fetch` của Worker **không ném lỗi** như Node; Cloudflare tự trả một trang `526 Invalid SSL certificate`.
- Bộ thu thập coi đó là trang thật, nên luật `tls.https-available` không thấy lỗi nào.
- Các mã 520–525 và 530 (máy chủ gốc không trả lời, bắt tay TLS lỗi) cũng gặp lỗi tương tự.

**Sửa.**
- `worker-fetch.ts`: trang 52x **do Cloudflare sinh** (có `server: cloudflare`) được coi là lỗi kết nối. Riêng 526 được ghi là lỗi chứng chỉ.
- Quét nhanh không chấm điểm và nêu rõ phát hiện nghiêm trọng kèm cách sửa (“chứng chỉ HTTPS không hợp lệ… gia hạn hoặc cài lại chứng chỉ…”).
- Quét lai tự chuyển sang container (Node đọc được chứng chỉ thật).
- Phản hồi 526 không do Cloudflare sinh vẫn giữ nguyên là một phản hồi bình thường.
- `ENGINE_VERSION` 11 → 12 để kết quả sai đang lưu đệm (vd. `expired.badssl.com` 76/C, còn hiệu lực tối đa 6 giờ) không bị dùng lại.

**Test hồi quy.**
- `worker-fetch.test.ts`: 526 → lỗi chứng chỉ; 520–525 và 530 → lỗi máy chủ gốc; 526 không do Cloudflare sinh → không đổi.
- `platform-scenarios.test.ts`: chứng chỉ hết hạn sau Cloudflare → `invalid_certificate`.

**Kiểm thử bản sửa.** Typecheck PASS · vitest 1157 PASS · `build:cf` + `wrangler deploy --dry-run` PASS. **Chưa** xác minh trên production: cần deploy, và IP kiểm thử đang bị giới hạn tốc độ trong 1 giờ.

## Không làm
- Không đổi luật chấm điểm.
- Không vượt giới hạn tốc độ hay kiểm soát bảo mật nào.
- Không merge, không deploy.
