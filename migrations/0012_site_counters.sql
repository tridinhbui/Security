-- Bộ đếm công khai cho trang chủ (số lượt quét đã hoàn tất). Chỉ là con số tổng, không gắn với người dùng hay website nào.
-- Cần bảng riêng vì lượt quét cũ bị xoá theo hạn lưu trữ và nhật ký quét nhanh chỉ giữ 2 ngày.
CREATE TABLE site_counters (
  name       TEXT PRIMARY KEY,
  value      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
-- Khởi tạo từ dữ liệu THẬT còn lưu (giới hạn dưới của số lượt đã chạy): quét đầy đủ đã hoàn tất + quét nhanh thật trong nhật ký hiện có.
INSERT INTO site_counters (name, value, updated_at) VALUES ('scans',
  (SELECT COUNT(*) FROM scans WHERE status = 'completed' AND cached = 0) +
  (SELECT COUNT(*) FROM quick_scan_log WHERE cached = 0 AND host <> 'invalid'),
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
