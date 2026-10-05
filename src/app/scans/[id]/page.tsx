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
      <div className="container-x max-w-2xl py-16 sm:py-24">
        <span className="chip-crit"><span className="size-1.5 rounded-full bg-crit" aria-hidden />Quét thất bại</span>
        <h1 className="mono mt-4 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{scan.normalized_url}</h1>
        <div className="term mt-8" role="alert">
          <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="ml-1">vibesec — lỗi</span></div>
          <div className="term-body"><p><span className="prompt">$</span> vibesec scan {scan.normalized_url}</p><p className="text-crit">✗ {scan.error_message ?? "Không thể hoàn tất lượt quét này."}</p><p className="text-faint">mã: {scan.error_code ?? "unknown"}</p></div>
        </div>
        <div className="mt-8 flex flex-wrap items-start gap-3"><RescanButton url={scan.input_url} label="Thử lại" /><Link href="/dashboard" className="btn-ghost btn-sm">Quay lại</Link></div>
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
      {scan.mode === "quick" && (
        <div className="container-x pt-6"><p className="panel-soft flex items-start gap-2 p-3 text-sm text-muted"><span className="chip-info shrink-0">quét nhanh</span>Lượt quét này bỏ qua việc tải file JavaScript, nên các kiểm tra về bí mật trong mã, source map và thư viện lỗi thời chỉ dựa trên phần HTML. Hãy quét đầy đủ để kiểm tra sâu hơn.</p></div>
      )}
      <Report data={data} actions={<ReportActions scanId={id} url={scan.input_url} />} />
      {earlier.length > 1 && (
        <div className="container-x -mt-4 pb-10 text-sm text-muted">
          <span>So sánh với lượt quét trước đó: </span>
          {earlier.map((e) => (
            <Link key={e.id} href={`/scans/${id}?vs=${e.id}`} className={`mono mr-3 text-xs underline underline-offset-2 hover:text-fg ${comparison?.previous.id === e.id ? "font-semibold text-fg" : ""}`}>{formatDate(e.completed_at ?? e.created_at)} ({e.score})</Link>
          ))}
        </div>
      )}
    </>
  );
}
