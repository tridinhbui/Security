"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { formatDate } from "@/lib/format";
import { SOURCE_LABEL } from "@/lib/project/launch";
import { bySeverity, VERDICT_LABEL, type ItemSource, type LaunchVerdict, type ProjectItem } from "@/lib/project/types";
import { SEV_CHIP } from "@/lib/format";
import { SEV_LABEL } from "@/lib/i18n";
import { MatMatSays } from "./matmat/MatMatSays";
import { useMatMat } from "./matmat/MatMatProvider";
import { ScoreRing } from "./motion/ScoreRing";
import { Group } from "./ProjectReport";

export interface LaunchSourceInfo { key: ItemSource; state: "scanned" | "missing" | "skipped"; at: string | null; label: string | null; rescanHref: string }
export interface LaunchDiffView { previousAt: string; previousVerdict: LaunchVerdict | null; previousScore: number | null; scoreDelta: number | null; resolved: ProjectItem[]; added: ProjectItem[]; remaining: ProjectItem[]; notRechecked: ProjectItem[] }
export interface LaunchReportData { id: string; label: string; createdAt: string; verdict: LaunchVerdict; score: number; grade: string; items: ProjectItem[]; blockers: ProjectItem[]; shoulds: ProjectItem[]; reasons: string[]; sources: LaunchSourceInfo[]; diff: LaunchDiffView | null; previousId: string | null }

const TONE: Record<LaunchVerdict, { box: string; text: string; dot: string; say: string }> = {
  ready: { box: "border-ok/30 bg-ok/5", text: "text-ok", dot: "bg-ok", say: "Tuyệt! Mình chưa thấy lỗi lớn nào trong những phần đã quét. Bạn có thể ra mắt, nhớ quét lại mỗi khi sửa code nhé." },
  fix_first: { box: "border-med/30 bg-med/5", text: "text-med", dot: "bg-med", say: "Gần xong rồi! Chưa có lỗi nặng nhưng còn vài việc nên làm trước khi ra mắt, để lúc có người dùng thật đỡ phải sửa gấp." },
  not_ready: { box: "border-crit/30 bg-crit/5", text: "text-crit", dot: "bg-crit", say: "Khoan đã! Còn những chỗ hở nghiêm trọng, ra mắt lúc này người lạ có thể lấy dữ liệu của bạn. Sửa các mục “Bắt buộc” bên dưới trước nhé." },
};

/** Production Readiness Check: kết luận rõ ràng, lỗi bắt buộc, checklist theo nhóm, và so sánh Trước/Sau. */
export function LaunchReport({ data }: { data: LaunchReportData }) {
  const { mode } = useMatMat();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const tone = TONE[data.verdict];

  const checklist = useMemo(() => {
    const bySource = new Map<ItemSource, Map<string, ProjectItem[]>>();
    for (const i of data.items) {
      if (!i.source || i.status === "info") continue;
      const g = bySource.get(i.source) ?? new Map<string, ProjectItem[]>();
      g.set(i.group, [...(g.get(i.group) ?? []), i]);
      bySource.set(i.source, g);
    }
    return bySource;
  }, [data.items]);

  async function recheck() {
    setBusy(true); setErr(null);
    try {
      const res = await fetch("/api/project-scans/launch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refreshFrom: data.id }) });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) { setErr(out.message ?? "Không thể đánh giá lại."); setBusy(false); return; }
      router.push(`/truoc-ra-mat/${out.id}`);
    } catch { setErr("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
  }

  return (
    <div className="relative">
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-x-0 top-0 -z-10 h-72" />
      <div className="container-x max-w-5xl py-10 sm:py-14">
        <header className="reveal">
          <p className="eyebrow">quét trước ra mắt <span aria-hidden>/</span> {formatDate(data.createdAt)}</p>
          <h1 className="mt-2 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{data.label}</h1>
        </header>

        <section className={`reveal mt-8 rounded-2xl border p-5 sm:p-7 ${tone.box}`} aria-label="Kết luận" style={{ ["--i" as string]: 1 }}>
          <div className="grid items-center gap-6 md:grid-cols-[auto_1fr] md:gap-10">
            <div className="mx-auto"><ScoreRing score={data.score} grade={data.grade} size={132} /></div>
            <div className="min-w-0">
              <p className="eyebrow">kết luận</p>
              <h2 className={`mt-1 flex items-center gap-3 text-3xl font-semibold tracking-tight sm:text-4xl ${tone.text}`}><span className={`size-3 rounded-full ${tone.dot}`} aria-hidden />{VERDICT_LABEL[data.verdict]}</h2>
              {mode === "beginner" ? <MatMatSays className="mt-3" text={tone.say} /> : <ul className="mt-3 space-y-1 text-[15px] text-fg/85">{data.reasons.map((r) => <li key={r}>• {r}</li>)}</ul>}
              <div className="mt-5 flex flex-wrap items-center gap-2">
                <button type="button" onClick={recheck} disabled={busy} className="btn-primary btn-sm">{busy ? <><span className="live-dot !bg-white" aria-hidden />Đang đánh giá…</> : "Đánh giá lại sau khi sửa"}</button>
                <span className="text-xs text-muted">Hãy quét lại các phần bạn đã sửa trước (bên dưới), rồi bấm nút này để xem Trước / Sau.</span>
              </div>
              {(data.blockers.length > 0 || data.shoulds.some((x) => x.status === "fail")) && <Link href={`/nho-chuyen-gia?kind=launch&id=${data.id}`} className="btn-ghost btn-sm mt-3 inline-flex">Nhờ chuyên gia xử lý các lỗi này</Link>}
              {err && <p role="alert" className="mt-2 text-sm text-crit">{err}</p>}
            </div>
          </div>
        </section>

        <section className="mt-6 grid gap-3 sm:grid-cols-3" aria-label="Nguồn dữ liệu">
          {data.sources.map((s) => (
            <div key={s.key} className="panel p-4">
              <div className="flex items-center justify-between gap-2"><h3 className="font-medium">{SOURCE_LABEL[s.key]}</h3>{s.state === "scanned" ? <span className="chip-ok">đã quét</span> : s.state === "skipped" ? <span className="chip-info">không áp dụng</span> : <span className="chip-med">chưa quét</span>}</div>
              <p className="mono mt-1.5 truncate text-[13px] text-muted">{s.label ?? "—"}</p>
              <p className="mt-0.5 text-xs text-faint">{s.at ? formatDate(s.at) : "Chưa có dữ liệu"}</p>
              {s.state !== "skipped" && <Link href={s.rescanHref} className="mt-2 inline-block text-[13px] font-medium text-accent hover:underline">{s.state === "scanned" ? "Quét lại phần này →" : "Quét ngay →"}</Link>}
            </div>
          ))}
        </section>

        {data.diff && <BeforeAfter diff={data.diff} now={{ verdict: data.verdict, score: data.score }} />}

        <Group title="Bắt buộc sửa trước khi ra mắt" hint="Những lỗi này có thể làm lộ dữ liệu hoặc cho phép chiếm quyền. Hãy sửa hết trước khi có người dùng thật." items={[...data.blockers]} openFirst showSource />
        <Group title="Nên sửa" hint="Không gây nguy hiểm ngay nhưng nên xử lý, hoặc phần chưa được kiểm tra." items={data.shoulds} showSource />
        {data.blockers.length === 0 && data.shoulds.length === 0 && <p className="reveal mt-10 rounded-xl border border-ok/25 bg-ok/5 px-4 py-3.5 text-[15px] text-ok">Không còn việc bắt buộc hay nên sửa trong những phần đã quét.</p>}

        <section className="mt-10" aria-label="Checklist">
          <h2 className="text-lg font-semibold tracking-tight">Checklist theo nhóm</h2>
          <p className="mt-0.5 text-sm text-muted">Mọi mục đã được kiểm tra thật trong các lượt quét bạn chọn.</p>
          <div className="mt-3 space-y-3">
            {[...checklist.entries()].map(([src, groups]) => (
              <div key={src} className="panel p-4">
                <h3 className="font-medium">{SOURCE_LABEL[src]}</h3>
                <ul className="mt-2 divide-y divide-line">
                  {[...groups.entries()].map(([name, items]) => {
                    const ok = items.filter((i) => i.status === "pass").length;
                    const bad = items.filter((i) => i.status === "fail");
                    const worst = bad.sort(bySeverity)[0];
                    return (
                      <li key={name}>
                        <details className="group">
                          <summary className="flex cursor-pointer items-center gap-3 py-2.5 text-[15px]">
                            <span className={`grid size-5 shrink-0 place-items-center rounded-full text-[11px] font-semibold text-white ${bad.length ? "bg-crit" : items.some((i) => i.status === "unknown") ? "bg-med" : "bg-ok"}`} aria-hidden>{bad.length ? "!" : items.some((i) => i.status === "unknown") ? "?" : "✓"}</span>
                            <span className="min-w-0 flex-1">{name}</span>
                            {worst && <span className={`${SEV_CHIP[worst.severity]} hidden sm:inline-flex`}>{SEV_LABEL[worst.severity]}</span>}
                            <span className="num text-sm text-muted">{ok}/{items.length} đạt</span>
                            <svg viewBox="0 0 24 24" className="size-4 text-faint transition-transform group-open:rotate-90" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg>
                          </summary>
                          <ul className="mb-3 ml-8 space-y-1.5 text-[14px]">
                            {items.map((i) => (
                              <li key={i.fingerprint + i.id} className="flex gap-2.5">
                                <span className={i.status === "pass" ? "text-ok" : i.status === "fail" ? "text-crit" : "text-med"} aria-hidden>{i.status === "pass" ? "✓" : i.status === "fail" ? "✕" : "?"}</span>
                                <span className={i.status === "pass" ? "text-muted" : ""}>{i.title}{mode === "technical" && <span className="mono text-faint"> · {i.id}</span>}</span>
                              </li>
                            ))}
                          </ul>
                        </details>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

function BeforeAfter({ diff, now }: { diff: LaunchDiffView; now: { verdict: LaunchVerdict; score: number } }) {
  const delta = diff.scoreDelta;
  return (
    <section className="reveal mt-8 panel p-5 sm:p-6" aria-label="Trước và sau" style={{ ["--i" as string]: 2 }}>
      <p className="eyebrow">trước / sau khi sửa</p>
      <div className="mt-3 grid items-center gap-4 sm:grid-cols-[1fr_auto_1fr]">
        <div className="panel-soft p-4"><p className="text-xs text-muted">Trước · {formatDate(diff.previousAt)}</p><p className="mt-1 font-medium">{diff.previousVerdict ? VERDICT_LABEL[diff.previousVerdict] : "—"}</p><p className="num text-2xl font-semibold text-muted">{diff.previousScore ?? "—"}<span className="text-sm font-normal">/100</span></p></div>
        <div className="text-center text-xl text-faint" aria-hidden>→</div>
        <div className="rounded-2xl border border-accent/25 bg-accent-soft/50 p-4"><p className="text-xs text-muted">Sau · bây giờ</p><p className="mt-1 font-medium">{VERDICT_LABEL[now.verdict]}</p><p className="num text-2xl font-semibold">{now.score}<span className="text-sm font-normal">/100</span>{delta !== null && delta !== 0 && <span className={`ml-2 text-sm font-medium ${delta > 0 ? "text-ok" : "text-crit"}`}>{delta > 0 ? `+${delta}` : delta}</span>}</p></div>
      </div>
      <dl className="mt-4 grid grid-cols-3 gap-3 text-center">
        <div><dt className="text-xs text-muted">Đã sửa</dt><dd className="num text-3xl font-semibold text-ok">{diff.resolved.length}</dd></div>
        <div><dt className="text-xs text-muted">Còn lại</dt><dd className={`num text-3xl font-semibold ${diff.remaining.length ? "text-med" : "text-faint"}`}>{diff.remaining.length}</dd></div>
        <div><dt className="text-xs text-muted">Mới xuất hiện</dt><dd className={`num text-3xl font-semibold ${diff.added.length ? "text-crit" : "text-faint"}`}>{diff.added.length}</dd></div>
      </dl>
      {diff.resolved.length > 0 && <ul className="mt-4 space-y-1 text-[14px]">{diff.resolved.slice(0, 12).map((i) => <li key={i.fingerprint} className="flex gap-2"><span className="text-ok" aria-hidden>✓</span><span className="text-muted line-through decoration-ok/50">{i.title}</span></li>)}</ul>}
      {diff.added.length > 0 && <ul className="mt-3 space-y-1 text-[14px]">{diff.added.slice(0, 8).map((i) => <li key={i.fingerprint} className="flex gap-2"><span className="text-crit" aria-hidden>+</span><span>{i.title}</span></li>)}</ul>}
      {diff.notRechecked.length > 0 && <p className="mt-3 text-[13px] text-muted">{diff.notRechecked.length} lỗi của lần trước thuộc phần chưa được quét lại, nên chưa tính là đã sửa. Hãy quét lại phần đó.</p>}
    </section>
  );
}
