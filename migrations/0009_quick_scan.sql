-- Quét nhanh miễn phí (không cần tài khoản): bộ nhớ đệm theo tên miền + nhật ký để giới hạn tốc độ theo IP/toàn hệ thống.
CREATE TABLE quick_scan_cache (
  host           TEXT PRIMARY KEY,
  engine_version INTEGER NOT NULL,
  payload        TEXT NOT NULL,          -- JSON QuickResult (chỉ kết quả đã tóm tắt, không có nội dung trang)
  created_at     TEXT NOT NULL
);
CREATE TABLE quick_scan_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,                  -- HMAC(ip); không lưu IP thô
  host    TEXT NOT NULL,
  cached  INTEGER NOT NULL DEFAULT 0,
  at      TEXT NOT NULL
);
CREATE INDEX quick_scan_log_ip_idx ON quick_scan_log (ip_hash, at);
CREATE INDEX quick_scan_log_at_idx ON quick_scan_log (at);
