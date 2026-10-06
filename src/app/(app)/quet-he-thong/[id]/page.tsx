import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { ProjectReport } from "@/components/ProjectReport";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { getProjectScan } from "@/lib/db/project-repo";
import { UUID } from "@/lib/http/guards";

export const metadata: Metadata = { title: "Báo cáo hệ thống", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const user = await getUser();
  if (!user) redirect(`/login?next=/quet-he-thong/${id}`);
  const s = await getProjectScan(await getDb(), user.id, id);
  if (!s || s.kind !== "system") notFound();
  const stack = s.stack === "firebase" ? "firebase" : "supabase";
  const m = s.meta as { site?: string };
  const names = (s.stack ?? "").split("+").map((x) => (x === "firebase" ? "Firebase" : "Supabase")).join(" + ");
  return <ProjectReport data={{ id: s.id, kind: "system", label: s.label, stackLabel: names, createdAt: s.created_at, score: s.score ?? 0, grade: s.grade ?? "F", items: s.items, rescanHref: m.site ? `/quet-he-thong?site=${encodeURIComponent(m.site)}` : `/quet-he-thong?stack=${stack}&ref=${encodeURIComponent(s.label)}`, notes: [m.site ? "Cấu hình được đọc tự động từ website và không được lưu lại." : "Khoá bạn nhập không được lưu. Để quét lại, hãy dán lại khoá công khai."] }} />;
}
