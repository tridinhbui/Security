import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { AdminHelpRow } from "@/components/AdminHelpRow";
import { getAdmin } from "@/lib/auth/admin";
import { getDb } from "@/lib/cf";
import { adminListHelp } from "@/lib/db/help-repo";

export const metadata: Metadata = { title: "Yêu cầu hỗ trợ", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function Page() {
  if (!(await getAdmin())) notFound();
  const rows = await adminListHelp(await getDb());
  const open = rows.filter((r) => r.status === "new").length;
  return (
    <div className="container-x max-w-5xl py-10 sm:py-14">
      <Link href="/admin" className="text-sm text-accent hover:underline">← Quản trị</Link>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight">Yêu cầu nhờ chuyên gia <span className="num ml-2 text-base font-normal text-muted">{open} mới · {rows.length} tổng</span></h1>
      <ul className="mt-6 space-y-3">{rows.map((r) => <AdminHelpRow key={r.id} r={r} />)}{!rows.length && <li className="text-muted">Chưa có yêu cầu nào.</li>}</ul>
    </div>
  );
}
