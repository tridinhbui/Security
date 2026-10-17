# Quy trình user testing: chất lượng giải thích của VibeSec

Mục tiêu: người không biết kỹ thuật vẫn **hiểu từng phát hiện và biết ai phải làm gì**, còn chuyên gia **kiểm chứng được lập luận**.
Không dùng LLM trong quy trình này; mọi chấm điểm do người quan sát thực hiện.

## 1. Người tham gia (4–5 người)

| Nhóm | Số người | Tiêu chí |
|---|---|---|
| A. Không kỹ thuật | 2 | Chủ shop/nhân viên marketing/kế toán; chưa từng chỉnh header hay DNS |
| B. Biết web cơ bản | 1 | Làm freelance/WordPress, biết hosting nhưng không chuyên bảo mật |
| C. Có kinh nghiệm | 1–2 | Dev backend/DevOps/pentester; kiểm chứng lập luận |

Không gộp kết quả giữa các nhóm; với 4–5 người **chỉ dùng để tìm chỗ khó hiểu, không dùng để tính tỉ lệ**.

## 2. Bộ 10 phát hiện

Chọn từ các website mẫu (`demo` hoặc benchmark corpus) để có đủ nhóm lỗi. Mỗi người đọc cùng 10 mục, **thứ tự xoay vòng** để tránh mệt mỏi dồn vào một mục.

| # | Luật / biến thể | Vì sao chọn | Mức chắc chắn |
|---|---|---|---|
| 1 | `headers.csp` thiếu hoàn toàn | Khái niệm trừu tượng (XSS) | Đã xác nhận |
| 2 | `headers.csp` yếu — `'unsafe-inline'` | Có/không có CSP dễ nhầm | Đã xác nhận (cấu hình) |
| 3 | `browser.cors` phản chiếu origin + credentials | Thuật ngữ khó, hậu quả nặng | Đã xác nhận (chỉ thử trang chủ) |
| 4 | `cookies.flags` thiếu Secure/HttpOnly | Nhiều cờ, dễ lẫn | Đã xác nhận |
| 5 | `tls.hsts` thiếu | Hậu quả gián tiếp | Đã xác nhận |
| 6 | `tls.certificate-expiry` còn 5 ngày | Có thời hạn, cần hành động nhanh | Đã xác nhận |
| 7 | `config.dns-email-security` — SPF `+all` | Người phụ trách là DNS, không phải dev | Đã xác nhận |
| 8 | `exposure.secrets` | Phải phân biệt khoá công khai và khoá bí mật | Rủi ro tiềm năng |
| 9 | `adv.dom-xss-flow` | Dấu hiệu tĩnh, độ tin cậy thấp | Rủi ro tiềm năng |
| 10 | `tls.https-available` trạng thái “unknown” | Thiếu dữ liệu — không được hiểu là lỗi hay an toàn | Chưa đủ dữ liệu |

Mục 8–10 kiểm tra riêng việc người đọc có **phân biệt được “xác nhận / tiềm năng / chưa kết luận”** hay không.

## 3. Kịch bản mỗi buổi (35–40 phút)

1. 3 phút: giới thiệu, nói rõ “chúng tôi đang thử văn bản, không thử bạn”; xin phép ghi chép. Không thu tên, email hay tên miền thật.
2. 25 phút: với mỗi mục, đưa trang giải thích (chế độ *Dễ hiểu* cho nhóm A/B, *Kỹ thuật* cho nhóm C), yêu cầu **nghĩ to**. Người quan sát **không gợi ý**.
3. Sau mỗi mục, hỏi đúng 4 câu (xem §4) rồi bấm 👍/🤔 thật trên giao diện.
4. 7 phút: phỏng vấn tổng quát — mục nào khó nhất, từ nào lạ, thứ gì thiếu.

## 4. Bốn câu hỏi và thang chấm

| Câu hỏi | Chấm |
|---|---|
| **Q1 Giải thích lại**: “Bạn kể lại cho người thân: website này đang gặp chuyện gì?” | 0 sai / 1 đúng một phần / 2 đúng ý chính |
| **Q2 Hậu quả**: “Nếu để nguyên, điều xấu gì có thể xảy ra? Chắc chắn đã xảy ra chưa?” | 0 nghĩ là đã bị hack / 1 mơ hồ / 2 hiểu là rủi ro, chưa chắc đã xảy ra |
| **Q3 Người xử lý**: “Việc này nên giao cho ai?” | 0 sai người / 1 đúng một phần / 2 đúng vai (dev/hosting/DNS/chủ) |
| **Q4 Bước sửa**: “Chỉ cho mình bước đầu tiên sẽ làm, và làm sao biết đã sửa xong.” | 0 không tìm được / 1 tìm được bước, không biết kiểm tra / 2 đúng cả hai |

Cộng thêm: thời gian đến lúc trả lời (giây), số lần quay lại đọc, từ khoá người đó hỏi lại.
Với mục 8–10 hỏi thêm **Q5**: “Đây là lỗi chắc chắn, rủi ro có thể xảy ra, hay chưa đủ thông tin?” (đúng = 1 điểm).

## 5. Tiêu chí đạt (theo từng mục, nhóm A)

- Q1 ≥ 1 và Q3 = 2 và Q4 ≥ 1 ở **ít nhất 2/2 người nhóm A** → đạt.
- Chỉ **1/2** đạt → “cần xem lại”, xếp theo độ ưu tiên dưới đây.
- Không ai đạt, hoặc bất kỳ người nào ở nhóm C chỉ ra **sai kỹ thuật** → viết lại ngay (sai kỹ thuật luôn ưu tiên cao nhất).
- Q2 = 0 (tưởng đã bị hack) ở bất kỳ người nào là lỗi **diễn đạt quá mạnh**, sửa phần `caveat`/`consequence`.

## 6. Kết hợp với dashboard `/admin/giai-thich`

- Dashboard cho **tín hiệu quy mô lớn** (nhiều người dùng thật); user testing cho **lý do** (vì sao khó hiểu).
- Chỉ ưu tiên theo dashboard khi mục đó có **≥ 10 phiếu** và cận dưới Wilson 95% của tỉ lệ “Chưa” ≥ 30%. Dưới 10 phiếu, chỉ đọc nhận xét, không rút kết luận.
- Một mục vừa dashboard-ưu-tiên vừa trượt user testing → sửa trước. Dashboard cao nhưng user testing đạt → kiểm tra xem người bấm “Chưa” có phải vì **không đồng ý với kết quả quét** (false positive) hơn là vì không hiểu.

## 7. Sau buổi test

1. Mỗi mục: bảng Q1–Q5 theo người, ghi chú nguyên văn câu người dùng nhầm (không ghi tên).
2. Sửa văn bản trong `src/lib/scanner/explain-more.ts` / `explain.ts` theo biến thể đã gây nhầm; **không** thêm LLM.
3. Chạy `npx vitest run src/lib/scanner/__tests__/explain-quality.test.ts` — bảo đảm vẫn đủ 63/63 luật, đủ trường `caveat`, `verify`, `certainty`.
4. Test lại với **1 người mới** cho các mục đã viết lại (người đã đọc rồi không còn “ngây thơ”).

## 8. Giới hạn cần ghi trong báo cáo

- 4–5 người không đại diện cho dân số: chỉ phát hiện vấn đề rõ rệt (nếu 2/2 nhóm A cùng hiểu sai thì gần như chắc là lỗi văn bản).
- Thang chấm do người quan sát thực hiện nên có chủ quan; hai người chấm độc lập một buổi để đối chiếu nếu có thể.
- Không đo hiệu quả sửa lỗi thật của website, chỉ đo khả năng hiểu và chọn đúng hành động.
