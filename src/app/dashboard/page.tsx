import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ScanForm } from "@/components/ScanForm";
import { Sparkline } from "@/components/Sparkline";
import { env } from "@/lib/env";
import { SEV_COLOR, SEV_LABEL } from "@/lib/format";
import { ScanTable } from "@/components/ScanTable";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

export const metadata: Metadata = { title: "Bảng điều khiển" };
export const dynamic = "force-dynamic";

export default async function Dashboard({ searchParams }: { searchParams: Promise<{ scan?: string }> }) {
  const { scan: prefill } = await searchParams;
  const user = await getUser();
  if (!user) redirect(`/login?next=${encodeURIComponent(prefill ? `/dashboard?scan=${encodeURIComponent(prefill)}` : "/dashboard")}`);
  const db = await getDb();

  const dayAgo = new Date(Date.now() - 86_400_000).toISOString();
  const [recent, used] = await Promise.all([repo.listScans(db, user.id, 50), repo.countScansSince(db, user.id, dayAgo)]);
  const quota = env.limits.dailyQuota;
  const completed = recent.filter((s) => s.status === "completed" && s.score !== null);

  // Trend: the most recently scanned site.
  const trendUrl = completed[0]?.normalized_url;
  const trend = completed.filter((s) => s.normalized_url === trendUrl).slice(0, 12).reverse().map((s) => ({ label: s.created_at, score: s.score! }));

  // Unresolved High/Critical = failing findings in the LATEST completed scan of each site.
  const latestPerSite = new Map<string, (typeof recent)[number]>();
  for (const s of completed) if (!latestPerSite.has(s.normalized_url)) latestPerSite.set(s.normalized_url, s);
  const latestIds = [...latestPerSite.values()].map((s) => s.id);
  const critical = await repo.openCriticalFindings(db, user.id, latestIds);
  const scanById = new Map(recent.map((s) => [s.id, s]));
  const unresolved = critical.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "critical" ? -1 : 1));

  return (
    <div className="mx-auto max-w-5xl px-5 py-10">
      <section aria-labelledby="scan-h">
        <h1 id="scan-h" className="text-2xl sm:text-3xl font-semibold tracking-tight">Quét một website</h1>
        <p className="text-sm text-muted mt-1.5 mb-5">Kiểm tra thụ động, không phá hoại. Thường hoàn tất trong chưa đầy 30 giây.</p>
        <div className="max-w-3xl"><ScanForm authed initialUrl={prefill ?? ""} autoStart={!!prefill} /></div>
      </section>

      <section className="mt-14 grid gap-12 md:grid-cols-3 border-t border-line pt-8" aria-label="Tổng quan">
        <div>
          <h2 className="text-sm font-medium text-muted">Lượt quét đã dùng (24 giờ)</h2>
          <p className="mt-2 num text-3xl font-semibold">{used}<span className="text-muted text-lg font-normal"> / {quota}</span></p>
          <div className="h-1 rounded bg-line mt-3" role="progressbar" aria-valuenow={used} aria-valuemax={quota} aria-label="Hạn mức quét mỗi ngày"><div className="h-1 rounded bg-fg" style={{ width: `${Math.min(100, (used / quota) * 100)}%` }} /></div>
        </div>
        <div className="md:col-span-2">
          <h2 className="text-sm font-medium text-muted">Xu hướng điểm{trendUrl ? <span className="text-faint"> · {new URL(trendUrl).host}</span> : null}</h2>
          <div className="mt-3">{trend.length ? <Sparkline points={trend} /> : <p className="text-sm text-muted">Chưa có lượt quét nào hoàn tất.</p>}</div>
        </div>
      </section>

      <section className="mt-12 border-t border-line pt-8" aria-labelledby="unresolved-h">
        <h2 id="unresolved-h" className="text-lg font-semibold tracking-tight">Vấn đề Cao &amp; Nghiêm trọng chưa xử lý</h2>
        {unresolved.length === 0 ? (
          <p className="text-sm text-muted mt-3">{completed.length ? "Không có vấn đề nào trong các lượt quét gần nhất. Tuyệt vời!" : "Chưa có gì để hiển thị cho đến khi lượt quét đầu tiên hoàn tất."}</p>
        ) : (
          <ul className="mt-3 divide-y divide-line border-y border-line">
            {unresolved.map((f, i) => {
              const s = scanById.get(f.scan_id);
              return (
                <li key={i}>
                  <Link href={`/scans/${f.scan_id}`} className="flex items-baseline gap-4 py-3 hover:bg-surface -mx-2 px-2 rounded">
                    <span className={`w-16 shrink-0 text-xs font-semibold uppercase ${SEV_COLOR[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
                    <span className="flex-1 min-w-0">{f.title}</span>
                    <span className="text-sm text-muted truncate max-w-40 hidden sm:block">{s?.host}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="mt-12 border-t border-line pt-8" aria-labelledby="recent-h">
        <div className="flex items-baseline justify-between">
          <h2 id="recent-h" className="text-lg font-semibold tracking-tight">Lượt quét gần đây</h2>
          <Link href="/scans" className="text-sm text-muted hover:text-fg">Tất cả báo cáo →</Link>
        </div>
        <ScanTable scans={recent.slice(0, 8)} />
      </section>
    </div>
  );
}
