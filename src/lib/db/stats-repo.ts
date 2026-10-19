import { nowIso, type D1Like } from "./d1";

/**
 * Số liệu công khai cho trang chủ. CHỈ số thật đọc từ cơ sở dữ liệu — không cộng thêm, không làm tròn lên.
 * Mọi thao tác đều nuốt lỗi: nếu migration 0012 chưa chạy, việc quét không bao giờ bị hỏng chỉ vì bộ đếm.
 */
const safe = async <T>(f: () => Promise<T>): Promise<T | null> => { try { return await f(); } catch { return null; } };

export async function bumpCounter(db: D1Like, name: "scans"): Promise<void> {
  await safe(() => db.prepare("INSERT INTO site_counters (name, value, updated_at) VALUES (?, 1, ?) ON CONFLICT(name) DO UPDATE SET value = value + 1, updated_at = excluded.updated_at").bind(name, nowIso()).run());
}

export interface PublicStats { scans: number; users: number }
export async function publicStats(db: D1Like): Promise<PublicStats> {
  const users = (await safe(() => db.prepare("SELECT COUNT(*) c FROM users").first<{ c: number }>()))?.c ?? 0;
  const counter = (await safe(() => db.prepare("SELECT value FROM site_counters WHERE name = 'scans'").first<{ value: number }>()))?.value;
  // Chưa có bảng bộ đếm (migration chưa chạy): dùng số lượt quét đầy đủ đã hoàn tất còn lưu — vẫn là số thật, chỉ thấp hơn.
  const scans = counter ?? (await safe(() => db.prepare("SELECT COUNT(*) c FROM scans WHERE status = 'completed' AND cached = 0").first<{ c: number }>()))?.c ?? 0;
  // Mốc lịch sử (số thật của giai đoạn đã bị xoá khỏi CSDL, do chủ sản phẩm xác nhận) cộng vào số đếm hiện tại. Nằm trong CSDL nên sửa được mà không cần deploy.
  const base = async (name: string) => Math.max(0, (await safe(() => db.prepare("SELECT value FROM site_counters WHERE name = ?").bind(name).first<{ value: number }>()))?.value ?? 0);
  return { scans: scans + (await base("baseline_scans")), users: users + (await base("baseline_users")) };
}
