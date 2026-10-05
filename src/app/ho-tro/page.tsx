import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ChatBox } from "@/components/ChatBox";
import { getUser } from "@/lib/auth/next";

export const metadata: Metadata = { title: "Hỗ trợ trực tiếp" };
export const dynamic = "force-dynamic";

export default async function Support() {
  const user = await getUser();
  if (!user) redirect("/login?next=/ho-tro");
  return (
    <div className="container-x max-w-2xl py-10 sm:py-14">
      <h1 className="reveal text-3xl font-semibold tracking-tight">Hỗ trợ trực tiếp</h1>
      <p className="reveal mt-2 text-sm text-muted" style={{ ["--i" as string]: 1 }}>Nhắn cho quản trị viên khi cần giúp đỡ hoặc muốn tăng hạn mức quét. Trang này tự cập nhật khi có phản hồi.</p>
      <div className="reveal mt-6" style={{ ["--i" as string]: 2 }}><ChatBox endpoint="/api/chat" me="user" placeholder="Nhập tin nhắn…" /></div>
      <p className="mt-4 text-xs text-faint">Minh bạch: để hỗ trợ và chống lạm dụng, quản trị viên có thể xem các địa chỉ bạn đã quét và thời lượng bạn sử dụng dịch vụ. Quản trị viên không thấy mật khẩu của bạn.</p>
    </div>
  );
}
