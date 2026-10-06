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
  return <ProjectReport data={{ kind: "system", label: s.label, stackLabel: stack === "firebase" ? "Firebase" : "Supabase", createdAt: s.created_at, score: s.score ?? 0, grade: s.grade ?? "F", items: s.items, rescanHref: `/quet-he-thong?stack=${stack}&ref=${encodeURIComponent(s.label)}`, notes: ["Khoá bạn nhập không được lưu. Để quét lại, hãy dán lại khoá công khai."] }} />;
}
