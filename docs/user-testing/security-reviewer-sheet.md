# Phiếu rà soát kỹ thuật (người nhóm C — có chuyên môn bảo mật)

Mục đích: tìm lời giải thích **sai về kỹ thuật** hoặc **phóng đại/giảm nhẹ rủi ro**. Đây là việc khác với “có dễ hiểu không” (nhóm A/B) và **không thể thay thế** bằng test tự động.

Không điền thay người rà soát. Người rà soát ghi theo mã luật (`finding_rule`), không ghi tên miền thật.

## Cách làm (khoảng 45–60 phút)
1. Mở `/demo` và một báo cáo thật trên site được phép. Với mỗi phát hiện được giao (tối thiểu 10 luật, ưu tiên: TLS, CSP/HSTS/cookies, CORS, mở lộ tệp/đường dẫn, DNS/email SPF-DMARC).
2. Với mỗi luật, đối chiếu **bốn thứ** và đánh dấu:

| Câu hỏi | OK / SAI / PHÓNG ĐẠI / GIẢM NHẸ / KHÔNG RÕ |
|---|---|
| Mô tả hiện tượng (“đã thấy gì”) có đúng với điều scanner thực sự quan sát? | |
| Giải thích hậu quả có đúng mức, không biến “thiếu cấu hình” thành “đã bị tấn công”? | |
| Bước sửa có đúng kỹ thuật và an toàn khi dán nguyên (không gây gián đoạn, không mở lỗ khác)? | |
| Lệnh/cách **kiểm tra lại** có thật sự chứng minh đã sửa, và chỉ đọc (không thăm dò)? | |

3. Các câu hỏi kiểm tra riêng: điểm cao có bị diễn đạt như “an toàn” không? Phát hiện *tiềm năng* có dùng từ chắc chắn không? Có chỗ nào hứa điều scanner không làm (vd. thăm dò `/.env`, `/.git`)?
4. Mỗi lỗi: ghi `mã luật · loại · đoạn văn nguyên văn · đề xuất sửa · nguồn tham chiếu (RFC/MDN/OWASP)`.

## Phân loại và hành động
- **SAI hoặc GIẢM NHẸ/PHÓNG ĐẠI nghiêm trọng**: sửa ngay, bất kể số phiếu; thêm test hồi quy.
- **KHÔNG RÕ**: để người quyết định kỹ thuật chốt, chưa sửa.
- Mọi bản viết lại phải giữ nguyên: mức độ nghiêm trọng, độ chắc chắn (chắc chắn/có thể), và người chịu trách nhiệm xử lý. Đổi một trong ba thứ này không phải “viết lại cho dễ hiểu”.

## Kết quả (người rà soát điền)
| finding_rule | loại lỗi | đoạn nguyên văn | đề xuất | nguồn |
|---|---|---|---|---|
|  |  |  |  |  |

Chưa có dòng nào = **chưa rà soát**, không phải “đã rà soát, không có lỗi”.
