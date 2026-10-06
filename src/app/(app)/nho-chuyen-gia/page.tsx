import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { HelpRequestForm } from "@/components/HelpRequestForm";
import { HelpRequestList } from "@/components/HelpRequestList";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { listMyHelp, type HelpKind } from "@/lib/db/help-repo";
import { UUID } from "@/lib/http/guards";
import { loadHelpSource } from "@/lib/project/help";

export const metadata: Metadata = { title: "Nhờ chuyên gia", robots: { index: false } };
export const dynamic = "force-dynamic";
const KINDS = ["website", "code", "system", "launch"];

export default async function Page({ searchParams }: { searchParams: Promise<{ kind?: string; id?: string; sent?: string }> }) {
  const sp = await searchParams;
  const user = await getUser();
  if (!user) redirect("/login?next=/nho-chuyen-gia");
  const db = await getDb();
  const src = sp.kind && KINDS.includes(sp.kind) && UUID.test(sp.id ?? "") ? await loadHelpSource(db, user.id, sp.kind as HelpKind, sp.id!) : null;
  const rows = await listMyHelp(db, user.id);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">nhờ chuyên gia</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Nhờ chuyên gia xử lý</h1>
      <MatMatSays className="mt-5 max-w-2xl" text="Quét giúp bạn thấy lỗi ở đâu. Nếu bạn không có thời gian hoặc không rành kỹ thuật, đội kỹ thuật sẽ xem và báo bạn cách làm cùng chi phí." />
      {sp.sent && <p role="status" className="mt-5 rounded-xl border border-ok/25 bg-ok/5 px-4 py-3 text-[15px] text-ok">Đã gửi yêu cầu. Đội kỹ thuật sẽ phản hồi kèm báo giá ngay tại trang này.</p>}
      {src && src.items.length > 0 && <div className="mt-8"><HelpRequestForm kind={src.kind} id={src.id} label={src.label} email={user.email} issues={src.items.map((i) => ({ fingerprint: i.fingerprint, title: i.title, severity: i.severity, group: i.group }))} /></div>}
      {src && src.items.length === 0 && <p className="mt-8 text-[15px] text-muted">Báo cáo này không có lỗi nào cần xử lý.</p>}
      {!src && <p className="mt-8 text-[15px] text-muted">Mở một báo cáo (website, mã nguồn, hệ thống hoặc trước ra mắt) và bấm “Nhờ chuyên gia xử lý” để chọn lỗi cần giúp.</p>}
      <section className="mt-12" aria-label="Yêu cầu của tôi"><h2 className="text-lg font-semibold tracking-tight">Yêu cầu của tôi</h2><HelpRequestList rows={rows} /></section>
    </div>
  );
}
