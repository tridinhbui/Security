-- Mốc lịch sử: số liệu THẬT của giai đoạn trước đã bị xoá khỏi cơ sở dữ liệu (lượt quét hết hạn lưu trữ, tài khoản đã xoá…) theo xác nhận của chủ sản phẩm.
-- Trang chủ hiển thị: số đếm hiện tại + mốc này. Sửa bằng UPDATE site_counters SET value = … WHERE name = '…' (không cần deploy lại).
INSERT INTO site_counters (name, value, updated_at) VALUES
  ('baseline_scans', 1000, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  ('baseline_users', 300, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
