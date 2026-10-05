-- Đăng nhập bằng Google. Người dùng Google-only có password_hash = 'oauth:google' (không phải định dạng scrypt
-- nên verifyPassword luôn trả false: không thể đăng nhập bằng mật khẩu cho tới khi họ chủ động đặt mật khẩu).
ALTER TABLE users ADD COLUMN google_sub TEXT;
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN avatar_url TEXT;
CREATE UNIQUE INDEX users_google_sub_idx ON users (google_sub) WHERE google_sub IS NOT NULL;
