import { AppSidebar } from "@/components/AppSidebar";
import { SiteFooter } from "@/components/SiteFooter";
import { SiteHeader } from "@/components/SiteHeader";
import { getAdmin } from "@/lib/auth/admin";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

/**
 * Khu vực sau đăng nhập: thanh điều hướng dọc + nội dung. Chưa đăng nhập thì dùng khung công khai (thanh trên + chân trang):
 * các trang riêng tư tự chuyển hướng tới /login kèm ?next= (layout không làm việc đó để không mất đường dẫn quay lại),
 * còn trang công khai dùng chung khu vực này (Phương pháp, Bản demo) vẫn xem được.
 */
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await getUser();
  if (!user) {
    return (
      <div className="flex min-h-dvh flex-col">
        <SiteHeader />
        <main id="main" className="flex-1">{children}</main>
        <SiteFooter />
      </div>
    );
  }
  const isAdmin = !!(await getAdmin());
  let supportUnread = 0, adminUnread = 0;
  try {
    const db = await getDb();
    [supportUnread, adminUnread] = await Promise.all([repo.unreadAdminReplies(db, user.id), isAdmin ? repo.adminUnreadChats(db) : Promise.resolve(0)]);
  } catch { /* huy hiệu chỉ là phần phụ: lỗi D1 không được làm hỏng trang */ }
  return (
    <div className="min-h-dvh bg-white lg:h-dvh lg:overflow-hidden lg:pl-64">
      <AppSidebar name={user.name} email={user.email} avatarUrl={user.avatar_url} isAdmin={isAdmin} supportUnread={supportUnread} adminUnread={adminUnread} />
      <main id="main" className="min-w-0 lg:h-full lg:overflow-y-auto">{children}</main>
    </div>
  );
}
