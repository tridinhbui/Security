-- Quét mã nguồn / hệ thống / trước ra mắt. Mỗi lượt quét là MỘT hàng; danh sách kiểm tra (đã ẩn bí mật) nằm trong `items` (JSON).
-- Không bao giờ lưu khoá/token người dùng nhập: chỉ lưu nhãn (tên repo, mã dự án) và kết quả đã được che.
CREATE TABLE project_scans (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL CHECK (kind IN ('code','system','launch')),
  label           TEXT NOT NULL,                  -- owner/repo · mã dự án · tên miền website
  stack           TEXT,                           -- github | supabase | firebase | NULL
  score           INTEGER CHECK (score BETWEEN 0 AND 100),
  grade           TEXT CHECK (grade IN ('A','B','C','D','F')),
  verdict         TEXT CHECK (verdict IN ('ready','fix_first','not_ready')),   -- chỉ dùng cho kind = launch
  severity_counts TEXT NOT NULL DEFAULT '{}',     -- JSON
  items           TEXT NOT NULL DEFAULT '[]',     -- JSON: ProjectItem[]
  meta            TEXT NOT NULL DEFAULT '{}',     -- JSON: thống kê, nguồn đã dùng (launch)
  created_at      TEXT NOT NULL,
  expires_at      TEXT NOT NULL
);
CREATE INDEX project_scans_user_idx ON project_scans (user_id, kind, created_at DESC);
CREATE INDEX project_scans_label_idx ON project_scans (user_id, kind, label, created_at);
CREATE INDEX project_scans_expiry_idx ON project_scans (expires_at);
