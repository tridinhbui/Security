# User testing VibeSec — 5 người dùng thật

**Trạng thái: CHƯA THỰC HIỆN.** Thư mục này chỉ chứa quy trình và biểu mẫu. `observations.csv` chỉ có hàng tiêu đề; mọi số liệu phải đến từ buổi quan sát thật. Không điền dữ liệu giả, không ước lượng thay người tham gia.

Mục tiêu: kiểm chứng rằng người **không biết bảo mật** (1) quét được, (2) hiểu đúng phát hiện, (3) biết ưu tiên, (4) tìm được cách sửa **và** cách kiểm tra lại. Bổ sung cho [user-testing-explanations.md](../user-testing-explanations.md) (bộ 10 phát hiện, dùng cho vòng chuyên sâu).

Tài liệu đi kèm: [facilitator-runsheet.md](./facilitator-runsheet.md) (kiểm tra trước buổi, cách đo, sau buổi) · [security-reviewer-sheet.md](./security-reviewer-sheet.md) (phiếu rà soát kỹ thuật cho người nhóm C).

## 1. Người tham gia (5)

| Nhóm | Số | Mô tả |
|---|---|---|
| A | 3 | Không kiến thức bảo mật/kỹ thuật (chủ shop, marketing, kế toán…) — **nhóm chính** |
| B | 1 | Biết web cơ bản (WordPress, freelance) |
| C | 1 | Có kinh nghiệm bảo mật/DevOps — kiểm tra **độ chính xác kỹ thuật** của lời giải thích |

Tuyển người không liên quan đội phát triển. Mỗi người chỉ tham gia một lần.

## 2. Website được quét (đạo đức & pháp lý)

Chỉ quét website **người tham gia sở hữu hoặc được chủ sở hữu cho phép bằng văn bản/tin nhắn**, hoặc website mẫu của chúng tôi (`/demo`, hoặc một site thử do chúng tôi dựng). Nếu người tham gia không có site, dùng site thử. Không bao giờ quét site của bên thứ ba chưa đồng ý. Giữ nguyên hạn mức quét của sản phẩm.

## 3. Năm nhiệm vụ (mỗi buổi 40–45 phút)

Người quan sát **không gợi ý**, chỉ ghi nhận. Người tham gia nghĩ to. Bấm đồng hồ ở mỗi nhiệm vụ.

| # | Nhiệm vụ (lời giao cho người dùng) | Hoàn thành khi | Đo |
|---|---|---|---|
| T1 | “Hãy kiểm tra bảo mật cho website này.” | Có báo cáo hiển thị mà không cần trợ giúp | completed 0/1, seconds, số lần bí |
| T2 | “Chọn 3 phát hiện bất kỳ và giải thích cho mình bằng lời của bạn.” (ghi **mỗi phát hiện một dòng**, `finding_rule` = mã luật) | Kể lại đúng ý chính | understanding 0–2 |
| T3 | “Nếu chỉ có 1 giờ, bạn làm gì trước? Vì sao?” | Chọn mục có mức độ/độ khẩn cao, lý do hợp lý | completed 0/1, understanding 0–2, đúng người xử lý `owner_correct` 0–2 |
| T4 | “Chỉ cho mình bước sửa đầu tiên và cách biết đã sửa xong.” (mỗi phát hiện đã chọn ở T2) | Tìm đúng bước sửa **và** cách kiểm tra lại | fix_found 0–2, verify_known 0/1 |
| T5 | “Phần giải thích này có dễ hiểu không?” → bấm 👍/🤔 thật trên sản phẩm, nói lý do | Bấm được và nêu điểm gây nhầm | clarity_vote, confusion_note |

Thêm 3 câu hỏi **kiểm tra hiểu sai tác hại** (ghi vào `confusion_note`):
1. “Điều xấu đã xảy ra với website chưa?” (đúng: chưa chắc/chưa biết — đây là cấu hình/rủi ro).
2. “Nếu điểm là 90/100 thì website an toàn chứ?” (đúng: không đảm bảo).
3. Với phát hiện *tiềm năng*/*chưa kết luận*: “Đây là lỗi chắc chắn hay chỉ là có thể?”

## 4. Thang chấm (0/1/2)

- **understanding**: 0 sai hoặc không nói được · 1 đúng một phần · 2 đúng ý chính **và** không phóng đại (không nói “đã bị hack”).
- **owner_correct**: 0 sai vai (dev/hosting/DNS/chủ website) · 1 một phần · 2 đúng.
- **fix_found**: 0 không tìm thấy · 1 thấy bước nhưng không biết kiểm tra lại · 2 đúng cả hai.
- Hai người quan sát chấm độc lập nếu có thể; bất đồng thì ghi cả hai và lấy điểm thấp hơn.

## 5. Tiêu chí quyết định (theo từng phát hiện)

Dùng `npx tsx scripts/usertest-summary.ts docs/user-testing/observations.csv`:

- `fix-first`: hiểu TB < 1, hoặc ≥ 2 người sai người xử lý / không thấy cách sửa / bấm “chưa rõ”.
- `review`: có ít nhất 1 tín hiệu xấu.
- `insufficient`: < 2 người đã đọc mục đó → **không kết luận**.
- Mọi sai kỹ thuật do nhóm C chỉ ra phải sửa ngay, bất kể điểm.
- Với 5 người **chỉ báo số đếm (3/5), không báo phần trăm** và không nói “tỉ lệ người dùng hiểu”.

Thứ tự ưu tiên sửa: (1) sai kỹ thuật, (2) hiểu thành “đã bị hack”, (3) không tìm được cách sửa/kiểm tra lại, (4) sai người xử lý, (5) từ vựng khó.

## 6. Quy trình

1. Đọc [consent-and-briefing.md](./consent-and-briefing.md) cho người tham gia, xin đồng ý miệng/ghi chú.
2. Chạy T1–T5; điền một dòng `observations.csv` cho mỗi (người × nhiệm vụ [× phát hiện ở T2/T4]). `participant_id` dạng `P01`…`P05`.
3. Sau mỗi buổi, ghi **nguyên văn** câu người dùng hiểu nhầm (không kèm tên/tên miền).
4. Khi đủ 5 người: chạy script tổng hợp, đối chiếu với `/admin/giai-thich` (chỉ tin dashboard khi mục có ≥ 10 phiếu), rồi sửa văn bản trong `src/lib/scanner/explain-more.ts`.
5. Kiểm lại với **1 người mới** cho các mục đã viết lại.
6. Chạy `npx vitest run` — bộ test giữ đủ 63/63 luật có giải thích, caveat và lệnh kiểm tra lại.

## 7. Dữ liệu cá nhân

Không ghi tên, email, số điện thoại, tên miền thật, ảnh màn hình có thông tin định danh. Ghi âm/quay màn hình chỉ khi có đồng ý riêng và xoá sau khi tổng hợp.

## 8. Kế hoạch phân tích đăng ký trước (viết TRƯỚC khi có dữ liệu, để không chọn tiêu chí theo kết quả)
- **Đơn vị**: người, không phải dòng. Báo `x/n` người; không báo phần trăm khi n ≤ 5.
- **Điều kiện “đủ để quyết định”**: ≥ 3 người nhóm A đã làm T1–T5 **và** ≥ 1 người nhóm C đã điền phiếu rà soát. Thiếu một trong hai → báo cáo ghi “chưa đủ”, không rút ra khuyến nghị viết lại.
- **Một giải thích chỉ được đưa vào danh sách “khó hiểu nhất”** khi: ≥ 2 người đã đọc mục đó **và** có ≥ 2 tín hiệu độc lập (hiểu sai / sai người xử lý / không tìm ra cách sửa / bấm “Chưa”) từ ≥ 2 người khác nhau; hoặc có ≥ 10 phiếu trên production và cận dưới Wilson ≥ 30%. Chưa đạt → ghi “chưa đủ dữ liệu”, **không xếp hạng**.
- **Sai kỹ thuật do nhóm C chỉ ra** được sửa ngay, không cần đủ ngưỡng ở trên.
- **Đổi giải thích**: giữ nguyên mức độ nghiêm trọng, độ chắc chắn và người xử lý; sau đó 1 người mới đọc lại (README §6.5).
- **Dừng sớm**: nếu hai người liên tiếp hiểu sai theo hướng “website đã bị hack”, dừng buổi tiếp theo và sửa trước.
- **Lịch gợi ý**: 5 buổi × 45 phút trong ≤ 2 tuần; điền CSV trong ngày; chạy công cụ tổng hợp sau buổi cuối, không giữa chừng (tránh thay đổi sản phẩm làm hỏng so sánh).
- **Không** sửa văn bản giải thích giữa các buổi trừ khi là lỗi kỹ thuật; ghi `commit` từ `/api/version` mỗi buổi để biết mỗi người thấy phiên bản nào.
