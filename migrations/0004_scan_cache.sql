-- Lượt quét "dùng lại kết quả" (không chạy container): không tính vào hạn mức/chi phí.
ALTER TABLE scans ADD COLUMN cached INTEGER NOT NULL DEFAULT 0;
CREATE INDEX scans_url_done_idx ON scans (normalized_url, status, completed_at);
