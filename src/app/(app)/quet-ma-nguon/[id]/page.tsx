import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { ProjectReport } from "@/components/ProjectReport";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { getProjectScan } from "@/lib/db/project-repo";
import { UUID } from "@/lib/http/guards";

export const metadata: Metadata = { title: "Báo cáo mã nguồn", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const user = await getUser();
  if (!user) redirect(`/login?next=/quet-ma-nguon/${id}`);
  const s = await getProjectScan(await getDb(), user.id, id);
  if (!s || s.kind !== "code") notFound();
  const m = s.meta as { files?: number; packages?: number; privateRepo?: boolean };
  return <ProjectReport data={{ kind: "code", label: s.label, stackLabel: m.privateRepo ? "GitHub · kho riêng tư" : "GitHub", createdAt: s.created_at, score: s.score ?? 0, grade: s.grade ?? "F", items: s.items, rescanHref: `/quet-ma-nguon?repo=${encodeURIComponent(s.label)}`, notes: [`Đã đọc ${m.files ?? 0} file và ${m.packages ?? 0} thư viện.`] }} />;
}
