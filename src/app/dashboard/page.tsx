import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";
import { ScanForm } from "@/components/ScanForm";
import { ScanTable } from "@/components/ScanTable";
import { Sparkline } from "@/components/Sparkline";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { env } from "@/lib/env";
import { SEV_CHIP } from "@/lib/format";
import { SEV_LABEL } from "@/lib/i18n";

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

  // Xu hướng: website được quét gần nhất.
  const trendUrl = completed[0]?.normalized_url;
  const trend = completed.filter((s) => s.normalized_url === trendUrl).slice(0, 12).reverse().map((s) => ({ label: s.created_at, score: s.score! }));

  // Vấn đề Cao/Nghiêm trọng chưa xử lý = phát hiện còn lỗi trong lượt quét hoàn tất MỚI NHẤT của từng website.
  const latestPerSite = new Map<string, (typeof recent)[number]>();
  for (const s of completed) if (!latestPerSite.has(s.normalized_url)) latestPerSite.set(s.normalized_url, s);
  const critical = await repo.openCriticalFindings(db, user.id, [...latestPerSite.values()].map((s) => s.id));
  const scanById = new Map(recent.map((s) => [s.id, s]));
  const unresolved = critical.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "critical" ? -1 : 1));
  const pct = Math.min(100, (used / quota) * 100);
  const name = user.name?.split(" ").slice(-1)[0] ?? user.email.split("@")[0];

  return (
    <div className="relative">
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-x-0 top-0 -z-10 h-64" />
      <div className="container-x py-10 sm:py-14">
        <section aria-labelledby="scan-h" className="reveal">
          <p className="eyebrow">xin chào, {name}</p>
          <h1 id="scan-h" className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Quét một website</h1>
          <p className="mb-6 mt-2 text-sm text-muted">Kiểm tra thụ động, không phá hoại. Thường hoàn tất trong chưa đầy 30 giây.</p>
          <div className="max-w-3xl"><ScanForm authed initialUrl={prefill ?? ""} autoStart={!!prefill} /></div>
        </section>

        <section className="mt-14 grid gap-6 md:grid-cols-3" aria-label="Tổng quan">
          <div className="panel reveal p-5" style={{ ["--i" as string]: 1 }}>
            <h2 className="eyebrow">lượt quét (24 giờ)</h2>
            <p className="mt-3 text-4xl font-semibold"><AnimatedNumber value={used} /><span className="mono text-base font-normal text-faint"> / {quota}</span></p>
            <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={used} aria-valuemax={quota} aria-label="Hạn mức quét mỗi ngày"><div className={`h-full rounded-full transition-[width] duration-1000 ${pct > 85 ? "bg-high" : "bg-accent"}`} style={{ width: `${pct}%` }} /></div>
          </div>
          <div className="panel reveal p-5 md:col-span-2" style={{ ["--i" as string]: 2 }}>
            <h2 className="eyebrow">xu hướng điểm{trendUrl ? <span className="normal-case tracking-normal"> · {new URL(trendUrl).host}</span> : null}</h2>
            <div className="mt-3">{trend.length ? <Sparkline points={trend} /> : <p className="text-sm text-muted">Chưa có lượt quét nào hoàn tất.</p>}</div>
          </div>
        </section>

        <section className="mt-14" aria-labelledby="unresolved-h">
          <h2 id="unresolved-h" className="text-xl font-semibold tracking-tight">Vấn đề Cao &amp; Nghiêm trọng chưa xử lý</h2>
          {unresolved.length === 0 ? (
            <p className="mt-3 flex items-center gap-2 text-sm text-muted">{completed.length ? <><span className="chip-ok">Ổn</span>Không có vấn đề nào trong các lượt quét gần nhất.</> : "Chưa có gì để hiển thị cho đến khi lượt quét đầu tiên hoàn tất."}</p>
          ) : (
            <ul className="mt-4 divide-y divide-line overflow-hidden rounded-xl border border-line bg-white shadow-crisp">
              {unresolved.map((f, i) => (
                <li key={i} className="reveal" style={{ ["--i" as string]: Math.min(i, 8) }}>
                  <Link href={`/scans/${f.scan_id}`} className="flex items-center gap-3 px-4 py-3 text-sm transition-colors hover:bg-surface">
                    <span className={`${SEV_CHIP[f.severity]} shrink-0`}>{SEV_LABEL[f.severity]}</span>
                    <span className="min-w-0 flex-1">{f.title}</span>
                    <span className="mono hidden max-w-44 truncate text-xs text-muted sm:block">{scanById.get(f.scan_id)?.host}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="mt-14" aria-labelledby="recent-h">
          <div className="flex items-baseline justify-between">
            <h2 id="recent-h" className="text-xl font-semibold tracking-tight">Lượt quét gần đây</h2>
            <Link href="/scans" className="text-sm font-medium text-accent hover:underline">Tất cả báo cáo →</Link>
          </div>
          <ScanTable scans={recent.slice(0, 8)} />
        </section>
      </div>
    </div>
  );
}
