# Phiếu điều phối buổi thử nghiệm (dành cho người quan sát)

Dùng cùng [README.md](./README.md) (quy trình, thang chấm) và [consent-and-briefing.md](./consent-and-briefing.md) (lời đọc). **Không điền dữ liệu giả; không tự đóng vai người tham gia.**

## A. Trước buổi (kiểm tra sẵn sàng — tất cả phải ✔)
- [ ] `curl -s https://security.tridinhbui0901.workers.dev/api/version` → `commit` là bản định thử; ghi lại `commit` + `workerVersionId` (ghi vào cột chú thích của buổi, không vào CSV).
- [ ] Website thử: của người tham gia, hoặc được chủ sở hữu cho phép, hoặc `/demo`. Không quét site bên thứ ba chưa đồng ý.
- [ ] Người tham gia đã được tuyển **độc lập với đội phát triển**; đã đọc lời giới thiệu và đồng ý (ghi có/không).
- [ ] Đồng hồ bấm giờ + bản `observations.csv` riêng cho buổi (đừng sửa dữ liệu của người khác).
- [ ] Biết trước: phiếu 👍/🤔 do người tham gia bấm là **phiếu thật** vào D1 production. Ghi giờ bắt đầu/kết thúc buổi để sau này đối chiếu với `/admin/giai-thich`. Không bấm thay họ, không bấm để thử.

## B. Cách đo (định nghĩa cố định để các buổi so sánh được)
| Chỉ số | Cách ghi |
|---|---|
| `seconds` của T1 | từ lúc đọc lời giao đến khi báo cáo hiện ra và người dùng chỉ vào nó |
| `seconds` của T4 (**thời gian tìm hướng dẫn**) | từ lúc đọc lời giao đến khi người dùng chỉ vào đúng bước sửa **và** nói cách kiểm tra lại; quá 5 phút thì dừng, `completed=0` |
| `completed` | 1 chỉ khi hoàn thành **không cần gợi ý**; bí > 2 phút mà phải chỉ → 0 và ghi “có trợ giúp” |
| `understanding` | 0/1/2 theo README §4, chấm **ngay sau** khi người dùng giải thích, trước khi bạn nói gì |
| `clarity_vote` | giá trị người dùng thật sự bấm ở T5; không bấm → `none` |
| `confusion_note` | nguyên văn câu hiểu nhầm, không tên/tên miền/IP |

## C. Quy tắc trong buổi
1. Chỉ đọc nguyên văn câu giao nhiệm vụ. Không giải thích thuật ngữ, không chỉ chỗ bấm, không nói “đúng rồi”.
2. Người dùng muốn dừng → dừng, không cần lý do. Ghi `completed` theo thực tế, không xoá dòng.
3. Hai người quan sát chấm độc lập nếu có; bất đồng thì lấy điểm thấp hơn.
4. Không ghi âm/quay màn hình nếu chưa có đồng ý riêng.

## D. Sau buổi
1. Điền CSV ngay trong ngày (trí nhớ phai nhanh).
2. Khi đủ người: `npx tsx scripts/usertest-summary.ts docs/user-testing/observations.csv`. Với ≤ 5 người **chỉ báo số đếm (3/5)**; cờ `insufficient` = không kết luận.
3. Đối chiếu `/admin/giai-thich`: chỉ tin một mục khi có **≥ 10 phiếu**; dưới đó chỉ là chuyện kể.
4. **Chỉ khi có bằng chứng** mới chọn các giải thích cần viết lại (xem README §5 và mục “điều kiện” trong báo cáo Phase 3.2). Mọi bản viết lại phải qua [security-reviewer-sheet.md](./security-reviewer-sheet.md).
