import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ScanTable } from "@/components/ScanTable";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

export const metadata: Metadata = { title: "Lịch sử quét" };
export const dynamic = "force-dynamic";

export default async function History() {
  const user = await getUser();
  if (!user) redirect("/login?next=/scans");
  const scans = await repo.listScans(await getDb(), user.id, 200);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <div className="reveal flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">{scans.length} lượt quét</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">Lịch sử quét</h1>
        </div>
        <Link href="/dashboard" className="btn-ghost btn-sm">← Bảng điều khiển</Link>
      </div>
      <p className="mt-3 text-sm text-muted">Báo cáo được lưu theo <Link className="font-medium text-accent hover:underline" href="/settings">thời gian lưu trữ</Link> bạn đã thiết lập.</p>
      <ScanTable scans={scans} />
    </div>
  );
}
