-- Yêu cầu nhờ chuyên gia xử lý lỗi. `issues` là ảnh chụp các mục người dùng chọn (đã che bí mật) để đội kỹ thuật xem
-- mà không cần quyền vào báo cáo của người dùng. Chưa thu tiền trong ứng dụng: báo giá nằm ở `quote`.
CREATE TABLE help_requests (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source_kind TEXT NOT NULL CHECK (source_kind IN ('website','code','system','launch')),
  source_id   TEXT NOT NULL,
  label       TEXT NOT NULL,
  issues      TEXT NOT NULL DEFAULT '[]',          -- JSON: [{title,severity,group,source,evidence[]}]
  note        TEXT NOT NULL DEFAULT '',
  contact     TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','quoted','in_progress','done','cancelled')),
  quote       TEXT NOT NULL DEFAULT '',            -- báo giá / phản hồi của đội kỹ thuật
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX help_requests_user_idx ON help_requests (user_id, created_at DESC);
CREATE INDEX help_requests_status_idx ON help_requests (status, created_at DESC);
