-- Phản hồi của người dùng ngay sau khi xem xong báo cáo (popup). Mỗi người chỉ gửi một lần cho mỗi lượt quét.
CREATE TABLE feedback (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rating     INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  tags       TEXT NOT NULL DEFAULT '',
  comment    TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE (user_id, scan_id)
);
CREATE INDEX feedback_created_idx ON feedback (created_at);
