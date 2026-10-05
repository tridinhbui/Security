-- Theo dõi thời lượng sử dụng + hộp thoại hỗ trợ trực tiếp giữa người dùng và quản trị viên.
ALTER TABLE users ADD COLUMN last_seen_at TEXT;
ALTER TABLE users ADD COLUMN usage_seconds INTEGER NOT NULL DEFAULT 0;

CREATE TABLE chat_messages (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,   -- luồng chat thuộc về người dùng này
  sender     TEXT NOT NULL CHECK (sender IN ('user','admin')),
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  read_at    TEXT                                                     -- phía còn lại đã đọc
);
CREATE INDEX chat_user_idx ON chat_messages (user_id, created_at);
CREATE INDEX chat_unread_idx ON chat_messages (sender, read_at);
