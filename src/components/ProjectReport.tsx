"use client";

import Link from "next/link";
import { useMemo } from "react";
import { plainScore } from "@/lib/feynman";
import { formatDate, SEV_CHIP, SEV_RAIL } from "@/lib/format";
import { CONFIDENCE_LABEL, SEV_LABEL } from "@/lib/i18n";
import { bySeverity, type ProjectItem } from "@/lib/project/types";
import { CopyButton } from "./CopyButton";
import { MatMatSays } from "./matmat/MatMatSays";
import { useMatMat } from "./matmat/MatMatProvider";
import { ScoreRing } from "./motion/ScoreRing";

export function CodeBlock({ code }: { code: string }) {
  return (
    <div className="term">
      <div className="term-body relative">
        <div className="absolute right-2 top-2"><CopyButton text={code} /></div>
        <pre className="overflow-x-auto whitespace-pre pr-16 text-[13px] leading-6">{code}</pre>
      </div>
    </div>
  );
}

const fixText = (i: ProjectItem) => [i.title, "", i.fix?.summary ?? "", ...(i.fix?.steps ?? []).map((s, k) => `${k + 1}. ${s}`), i.fix?.snippet ? `\n${i.fix.snippet.code}` : ""].join("\n").trim();

/** Một mục kiểm tra: tiêu đề + mức độ; mở ra là giải thích đời thường, bằng chứng đã che và cách sửa cụ thể. */
export function ItemCard({ item, defaultOpen = false, showSource = false }: { item: ProjectItem; defaultOpen?: boolean; showSource?: boolean }) {
  const { mode } = useMatMat();
  const technical = mode === "technical";
  const fail = item.status === "fail";
  const rail = fail ? SEV_RAIL[item.severity] : item.status === "pass" ? "border-l-ok/50" : "border-l-line-strong";
  const SRC = { website: "Website", code: "Mã nguồn", system: "Hệ thống" } as const;
  return (
    <li>
      <details open={defaultOpen} className={`group panel border-l-[3px] ${rail} transition-shadow open:shadow-pop`}>
        <summary className="flex cursor-pointer items-start gap-3 px-4 py-3.5 transition-colors hover:bg-surface/70 sm:items-center">
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              {fail ? <span className={SEV_CHIP[item.severity]}>{SEV_LABEL[item.severity]}</span> : item.status === "pass" ? <span className="chip-ok">Đạt</span> : <span className="chip-info">{item.status === "unknown" ? "Chưa kiểm tra được" : "Ghi chú"}</span>}
              <span className="font-medium leading-snug">{item.title}</span>
            </span>
            <span className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-muted">
              {showSource && item.source && <span>{SRC[item.source]}</span>}
              <span>{item.group}</span>
              {technical && <span className="mono text-faint">· {item.id} · độ chắc chắn {CONFIDENCE_LABEL[item.confidence]}</span>}
            </span>
          </span>
          <svg viewBox="0 0 24 24" className="mt-1 size-4 shrink-0 text-faint transition-transform duration-200 group-open:rotate-90 sm:mt-0" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg>
        </summary>
        <div className="grid gap-x-8 gap-y-5 border-t border-line px-4 py-5 md:grid-cols-2">
          <div className="min-w-0 space-y-5">
            <Block title={technical ? "Chúng tôi phát hiện" : "Chuyện gì đang xảy ra"}><p className="text-[15px] leading-relaxed">{item.summary}</p></Block>
            {item.evidence.length > 0 && <Block title="Bằng chứng (đã ẩn giá trị bí mật)"><div className="term"><ul className="term-body mono space-y-0.5 break-all text-[12.5px] leading-6">{item.evidence.map((e, k) => <li key={k}>{e}</li>)}</ul></div></Block>}
            <Block title={technical ? "Tác động tiềm ẩn" : "Vì sao nên quan tâm"}><p className="text-[15px] leading-relaxed text-muted">{item.why}</p></Block>
            {technical && item.technical && <Block title="Chi tiết kỹ thuật"><p className="mono whitespace-pre-wrap text-xs leading-relaxed text-muted">{item.technical}</p></Block>}
          </div>
          <div className="min-w-0 space-y-5">
            {item.fix && (
              <Block title={technical ? "Cách khắc phục" : "Bạn cần làm gì"}>
                <p className="rounded-lg bg-surface px-3.5 py-2.5 text-[15px] leading-relaxed">{item.fix.summary}</p>
                {item.fix.steps && item.fix.steps.length > 0 && <ol className="mt-3 list-decimal space-y-1.5 pl-5 text-[15px] leading-relaxed text-muted marker:text-faint">{item.fix.steps.map((s, k) => <li key={k}>{s}</li>)}</ol>}
                {item.fix.snippet && <div className="mt-3"><p className="mb-1.5 text-xs text-muted">{item.fix.snippet.label}</p><CodeBlock code={item.fix.snippet.code} /></div>}
                {fail && <div className="mt-3 flex items-center gap-2 text-xs text-muted"><CopyButton text={fixText(item)} />Chép hướng dẫn này để dán cho AI (Cursor, Claude Code…)</div>}
              </Block>
            )}
            {item.action && <Link href={item.action.href} className="btn-primary btn-sm inline-flex">{item.action.label} →</Link>}
          </div>
        </div>
      </details>
    </li>
  );
}

export function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return <div><h3 className="eyebrow mb-1.5">{title}</h3>{children}</div>;
}

export interface ProjectReportData {
  id: string;
  kind: "code" | "system";
  label: string;
  stackLabel: string;
  createdAt: string;
  score: number;
  grade: string;
  items: ProjectItem[];
  notes: string[];
  rescanHref: string;
}

/** Báo cáo quét mã nguồn / hệ thống: chia theo mức rủi ro, ngôn ngữ đời thường ở chế độ Dễ hiểu. */
export function ProjectReport({ data }: { data: ProjectReportData }) {
  const { mode } = useMatMat();
  const g = useMemo(() => {
    const fails = data.items.filter((i) => i.status === "fail");
    return {
      urgent: fails.filter((i) => i.severity === "critical" || i.severity === "high").sort(bySeverity),
      medium: fails.filter((i) => i.severity === "medium"),
      low: fails.filter((i) => i.severity === "low" || i.severity === "info"),
      notes: data.items.filter((i) => i.status === "unknown" || i.status === "info"),
      passed: data.items.filter((i) => i.status === "pass"),
      fails,
    };
  }, [data.items]);
  const what = data.kind === "code" ? "mã nguồn" : "hệ thống";

  return (
    <div className="relative">
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-x-0 top-0 -z-10 h-72" />
      <div className="container-x max-w-5xl py-10 sm:py-14">
        <header className="reveal">
          <p className="eyebrow">quét {what} <span aria-hidden>/</span> {formatDate(data.createdAt)}</p>
          <h1 className="mono mt-2 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{data.label}</h1>
          <p className="mt-2 flex flex-wrap gap-1.5"><span className="chip-info">{data.stackLabel}</span><span className="chip-info">chỉ đọc · không thay đổi gì</span></p>
        </header>

        <section className="reveal mt-8 rounded-2xl border border-line bg-white p-5 shadow-card sm:p-7" aria-label="Tóm tắt">
          <div className="grid items-center gap-6 md:grid-cols-[auto_1fr] md:gap-10">
            <div className="mx-auto"><ScoreRing score={data.score} grade={data.grade} size={150} /></div>
            <div className="min-w-0">
              {mode === "beginner"
                ? <MatMatSays text={`Mình xem giúp bạn rồi nè! ${plainScore(data.score, g.fails.length, g.urgent.length)}`} />
                : <p className="text-[15px] leading-relaxed">Điểm {data.score}/100 · hạng {data.grade}. {g.fails.length} vấn đề ({g.urgent.length} nghiêm trọng/cao), {g.passed.length} mục đạt.</p>}
              <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
                {[["Cần sửa ngay", g.urgent.length, "text-crit"], ["Nên sửa", g.medium.length, "text-med"], ["Cải thiện thêm", g.low.length, "text-low"], ["Đã ổn", g.passed.length, "text-ok"]].map(([l, n, c]) => (
                  <div key={String(l)}><dt className="text-xs text-muted">{l}</dt><dd className={`num mt-0.5 text-3xl font-semibold ${Number(n) ? c : "text-faint"}`}>{n}</dd></div>
                ))}
              </dl>
              {data.notes.map((n) => <p key={n} className="mt-3 text-[13px] text-muted">{n}</p>)}
            </div>
          </div>
          <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-4">
            <Link href={data.rescanHref} className="btn-ghost btn-sm">Quét lại sau khi sửa</Link>
            <Link href="/truoc-ra-mat" className="btn-ghost btn-sm">Đánh giá trước ra mắt</Link>
            {g.fails.length > 0 && <Link href={`/nho-chuyen-gia?kind=${data.kind}&id=${data.id}`} className="btn-primary btn-sm">Nhờ chuyên gia xử lý</Link>}
            <span className="text-xs text-faint">Giá trị bí mật luôn được ẩn. Chúng tôi không lưu khoá hay token bạn nhập.</span>
          </div>
        </section>

        <Group title="Cần sửa ngay" hint="Rủi ro cao: nên xử lý trước khi làm bất cứ việc gì khác." items={g.urgent} openFirst />
        <Group title="Nên sửa" hint="Rủi ro vừa: sửa trong tuần này." items={g.medium} />
        <Group title="Có thể cải thiện" hint="Rủi ro thấp: làm khi rảnh." items={g.low} />
        <Group title="Chưa kiểm tra được / để biết" hint="Phần chúng tôi không thể xác nhận hoặc chỉ ghi nhận." items={g.notes} />
        {g.fails.length === 0 && <p className="reveal mt-10 rounded-xl border border-ok/25 bg-ok/5 px-4 py-3.5 text-[15px] text-ok">Không phát hiện vấn đề nào trong những phần đã quét. Hãy quét lại mỗi khi có thay đổi lớn.</p>}
        {g.passed.length > 0 && (
          <section className="mt-10" aria-label="Đã kiểm tra, ổn">
            <details className="panel group">
              <summary className="flex cursor-pointer items-center justify-between px-4 py-3.5 text-[15px] font-medium"><span>Đã kiểm tra và ổn <span className="chip-ok ml-2">{g.passed.length}</span></span><svg viewBox="0 0 24 24" className="size-4 text-faint transition-transform group-open:rotate-90" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg></summary>
              <ul className="space-y-1.5 border-t border-line px-4 py-3 text-[14px]">{g.passed.map((p) => <li key={p.fingerprint + p.id} className="flex gap-2.5"><span className="mt-0.5 text-ok" aria-hidden>✓</span><span><span className="font-medium">{p.title}</span>{mode === "technical" ? <span className="mono text-faint"> · {p.id}</span> : null}<span className="block text-muted">{p.summary}</span></span></li>)}</ul>
            </details>
          </section>
        )}
      </div>
    </div>
  );
}

export function Group({ title, hint, items, openFirst = false, showSource = false }: { title: string; hint: string; items: ProjectItem[]; openFirst?: boolean; showSource?: boolean }) {
  if (!items.length) return null;
  return (
    <section className="mt-10" aria-label={title}>
      <div className="flex items-baseline gap-3"><h2 className="text-lg font-semibold tracking-tight">{title}</h2><span className="num text-sm text-muted">{items.length}</span></div>
      <p className="mt-0.5 text-sm text-muted">{hint}</p>
      <ul className="mt-3 space-y-3">{items.map((i, k) => <ItemCard key={i.fingerprint + i.id} item={i} defaultOpen={openFirst && k === 0} showSource={showSource} />)}</ul>
    </section>
  );
}
