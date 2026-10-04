import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { Report } from "@/components/Report";
import { ReportActions } from "@/components/ReportActions";
import { RescanButton } from "@/components/RescanButton";
import { ScanProgress } from "@/components/ScanProgress";
import { formatDate } from "@/lib/format";
import { UUID } from "@/lib/http/guards";
import { toReportData } from "@/lib/report-data";
import { loadComparison, loadReport } from "@/lib/reports";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

export const metadata: Metadata = { title: "Báo cáo", robots: { index: false } };
export const dynamic = "force-dynamic";

export default async function ScanPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ vs?: string }> }) {
  const { id } = await params;
  const { vs } = await searchParams;
  if (!UUID.test(id)) notFound();
  const user = await getUser();
  if (!user) redirect(`/login?next=/scans/${id}`);
  const db = await getDb();

  const view = await loadReport(db, user.id, id, { includeTargets: true }); // only the owner can load it
  if (!view) notFound();
  const { scan } = view;

  if (scan.status === "failed") {
    return (
      <div className="mx-auto max-w-xl px-5 py-20">
        <p className="text-sm text-muted">Quét thất bại</p>
        <h1 className="text-2xl font-semibold tracking-tight break-all mt-1">{scan.normalized_url}</h1>
        <p className="mt-6 text-high">{scan.error_message ?? "Không thể hoàn tất lượt quét này."}</p>
        <div className="mt-8 flex gap-3 items-start"><RescanButton url={scan.input_url} label="Thử lại" /><Link href="/dashboard" className="h-9 px-4 inline-flex items-center rounded-md border border-line-strong text-sm">Quay lại</Link></div>
      </div>
    );
  }
  if (scan.status !== "completed") return <ScanProgress scanId={id} initialStatus={scan.status} url={scan.normalized_url} />;

  // Comparison: an explicit earlier scan (?vs=) or, by default, the previous scan of the same URL.
  const comparison = await loadComparison(db, view, UUID.test(vs ?? "") ? vs : undefined);
  const earlier = await repo.earlierCompleted(db, user.id, scan.normalized_url, scan.created_at, 6);
  const data = toReportData(view, { variant: "owner", comparison });

  return (
    <>
      <Report data={data} actions={<ReportActions scanId={id} url={scan.input_url} />} />
      {earlier.length > 1 && (
        <div className="mx-auto max-w-5xl px-5 -mt-4 pb-10 text-sm text-muted">
          <span>So sánh với lượt quét trước đó: </span>
          {earlier.map((e) => (
            <Link key={e.id} href={`/scans/${id}?vs=${e.id}`} className={`mr-3 underline underline-offset-2 hover:text-fg ${comparison?.previous.id === e.id ? "text-fg" : ""}`}>{formatDate(e.completed_at ?? e.created_at)} ({e.score})</Link>
          ))}
        </div>
      )}
    </>
  );
}
