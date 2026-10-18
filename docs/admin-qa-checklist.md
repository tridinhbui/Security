# Checklist E2E cho `/admin/giai-thich` (chủ repo thực hiện)

Mục đích: xác nhận trang quản trị độ rõ giải thích hoạt động đúng với **tài khoản admin thật** trên production. Tôi (Claude) **không đăng nhập admin production và không tạo phiếu để thử** — mọi ô dưới đây cần người làm. Không bấm 👍/🤔 chỉ để thử trên production: phiếu đó là dữ liệu thật và không được xoá/sửa.

Điều kiện: email của bạn nằm trong `ADMIN_EMAILS` **và** tài khoản đã liên kết Google.

## A. Quyền truy cập (4 trường hợp, ghi kết quả thật)
| # | Cách thử | Kết quả đúng | Kết quả thật |
|---|---|---|---|
| A1 | Cửa sổ ẩn danh, mở `/admin/giai-thich` | 404 (không chuyển hướng đăng nhập, không lộ tồn tại trang) | |
| A2 | Đăng nhập tài khoản thường (không phải admin) | 404 | |
| A3 | Admin nhưng đăng nhập bằng email/mật khẩu chưa liên kết Google (nếu có) | 404 | |
| A4 | Admin đã liên kết Google | 200, thấy trang | |
| A5 | `curl -s -o /dev/null -w '%{http_code}' https://security.tridinhbui0901.workers.dev/admin/giai-thich` | 404 | |

## B. Trạng thái không có dữ liệu (production hiện có 0 phiếu — kiểm tra đúng lúc này)
- [ ] Dòng tổng: `0 phiếu · 0 chưa rõ (0%)`, không có `NaN`.
- [ ] Bảng chính: một dòng “Chưa có phiếu nào.”
- [ ] Bảng “Theo chế độ hiển thị”: chỉ có dòng **Tất cả** với `0 / 0` và nhãn `mẫu nhỏ (n=0)`; không dòng luật nào, không chip “ưu tiên/ổn”.
- [ ] “Nhận xét gần đây”: “Chưa có nhận xét.”
- [ ] **0 phiếu không được hiển thị như “dễ hiểu”** (không có chip xanh “ổn” ở bất kỳ ô nào).

## C. Thống kê (chỉ khi đã có phiếu thật; không tạo phiếu giả)
- [ ] Tổng số phiếu bằng `SELECT COUNT(*) FROM explain_feedback` (truy vấn chỉ-đọc trong D1 console).
- [ ] Một mục có < 10 phiếu: chip `mẫu nhỏ (n=…)`, **không** có “ưu tiên viết lại”, kể cả khi 100% là “Chưa”.
- [ ] Một mục ≥ 10 phiếu: nhãn phụ thuộc cận dưới Wilson 95% (di chuột xem “Cận dưới 95%”): ≥ 30% = ưu tiên, tỉ lệ ≥ 25% = theo dõi, còn lại = ổn.
- [ ] Số trong bảng “theo chế độ” cộng lại khớp bảng chính (cùng tổng).
- [ ] Nhận xét hiển thị **không chứa** tên miền, email, IP, URL, token (đã bị thay bằng `[đã ẩn]`); nếu thấy dữ liệu nhận dạng được còn sót → ghi lại **mã luật và thời điểm**, không dán nội dung vào chat/issue công khai.
- [ ] Nhớ: số phiếu là **cận dưới số người** (IP dùng chung dùng chung một phiếu) và dễ bị bơm nếu có người cố ý (xem báo cáo §12).

## D. Mobile (điện thoại thật, hoặc DevTools 375×812)
- [ ] Không có thanh cuộn ngang của cả trang; hai bảng cuộn ngang **trong khung** của chúng.
- [ ] Chữ chip không bị cắt; dòng “← Quản trị” bấm được.
- [ ] Trên báo cáo (`/demo`): nút 👍 Có / 🤔 Chưa cao ≥ 40px, bấm bằng ngón tay không nhầm nút kề.
- [ ] Chatbot: gõ nhiều dòng, ô nhập tự cao lên (tối đa ~168px rồi cuộn trong ô), Enter gửi, Shift+Enter xuống dòng, bộ đếm hiện từ 1500 ký tự.

## E. Nhật ký
Ghi: ngày, thiết bị/trình duyệt, người thực hiện, `commit` từ `/api/version`, kết quả từng ô, ảnh chụp (đã che thông tin cá nhân). Ô nào sai → mở issue kèm mã luật; **không sửa dữ liệu phiếu để cho đẹp**.
