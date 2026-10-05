import { getDb } from "../cf";
import * as repo from "../db/repo";
import { env } from "../env";
import { getUser, type SessionUser } from "./next";

/**
 * Quản trị viên = email nằm trong ADMIN_EMAILS VÀ tài khoản đã liên kết Google (email do Google xác minh).
 * Đăng ký bằng mật khẩu không xác minh email, nếu không ai đó có thể đăng ký trước bằng email của quản trị viên.
 */
export async function getAdmin(): Promise<SessionUser | null> {
  const user = await getUser();
  if (!user || !env.adminEmails.includes(user.email.toLowerCase())) return null;
  return (await repo.hasGoogleLink(await getDb(), user.id)) ? user : null;
}
