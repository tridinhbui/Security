-- Quét nhanh + bộ nhớ đệm kết quả TLS (chứng chỉ ít đổi → không cần đánh thức container mỗi lượt quét).
ALTER TABLE scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'full' CHECK (mode IN ('full','quick'));

CREATE TABLE tls_cache (
  host       TEXT PRIMARY KEY,
  data       TEXT NOT NULL,        -- JSON TlsInspection (chỉ thông tin công khai của chứng chỉ)
  fetched_at TEXT NOT NULL
);
