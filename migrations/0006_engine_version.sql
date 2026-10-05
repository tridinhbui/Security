-- Phiên bản bộ luật dùng để chấm lượt quét; chỉ dùng lại kết quả (bộ nhớ đệm) khi trùng phiên bản hiện hành.
ALTER TABLE scans ADD COLUMN engine_version INTEGER NOT NULL DEFAULT 0;
