-- "Giải thích này có rõ không?": phiếu bình chọn theo từng phát hiện để biết mục nào khó hiểu.
-- Riêng tư: KHÔNG lưu tên miền, URL hay IP thô. Chỉ lưu mã luật + khoá biến thể (đã lọc) + người bình chọn dạng băm.
CREATE TABLE explain_feedback (
  id         TEXT PRIMARY KEY,
  rule_id    TEXT NOT NULL,
  variant    TEXT NOT NULL DEFAULT '',
  verdict    TEXT NOT NULL CHECK (verdict IN ('clear','unclear')),
  source     TEXT NOT NULL CHECK (source IN ('quick','full')),
  mode       TEXT NOT NULL DEFAULT '',
  comment    TEXT NOT NULL DEFAULT '',
  voter_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (voter_hash, rule_id, variant)
);
CREATE INDEX explain_feedback_rule_idx ON explain_feedback (rule_id, verdict);
CREATE INDEX explain_feedback_voter_idx ON explain_feedback (voter_hash, updated_at);
