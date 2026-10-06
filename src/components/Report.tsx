"use client";

import { useEffect, useMemo, useState } from "react";
import { glossaryFor, PLAIN_TITLES } from "@/lib/beginner";
import type { TargetView } from "@/lib/db-types";
import { formatDate, scoreColor, SEV_BAR, SEV_CHIP, SEV_COLOR, SEV_RAIL } from "@/lib/format";
import { buildRoadmap, buildSummary, CONFIDENCE_FACTOR, EFFORT_LABEL, effortFor, OWASP_MAP, scoringTable, toMarkdown } from "@/lib/guidance";
import { CATEGORY_LABEL, CONFIDENCE_LABEL, SEV_LABEL } from "@/lib/i18n";
import { CATEGORIES, SEVERITIES, type Finding, type Severity } from "@/lib/scanner/types";
import { buildAllPrompt, buildFixPrompt } from "@/lib/ai-prompt";
import { FEYNMAN, plainScore, PLAIN_SEV } from "@/lib/feynman";
import { CopyButton } from "./CopyButton";
import { FeedbackModal } from "./matmat/FeedbackModal";
import { MatMatSays } from "./matmat/MatMatSays";
import { useMatMat } from "./matmat/MatMatProvider";
import { AnimatedNumber } from "./motion/AnimatedNumber";
import { ScoreRing } from "./motion/ScoreRing";
import { TermTyper, Typed, type TermLine } from "./motion/Typed";
import { RescanButton } from "./RescanButton";

export interface ReportData {
  /** Id lượt quét (dùng để chỉ phát hiệu ứng xuất kết quả một lần cho mỗi báo cáo). */
  id?: string;
  url: string;
  host: string;
  scannedAt: string;
  score: number;
  grade: string;
  categoryScores: Record<string, number | null>;
  severityCounts: Record<Severity, number>;
  platforms: string[];
  requestCount?: number | null;
  findings: Finding[];
  targets?: TargetView[];
  comparison?: { previousScore: number; previousAt: string; scoreDelta: number; newFindings: Finding[]; resolvedFindings: Finding[]; unchanged: number } | null;
  /** Hiện nút Quét lại (chỉ chủ báo cáo). */
  canRescan?: boolean;
  variant?: "owner" | "shared" | "demo";
  disclaimer: string;
}

import type { Mode } from "./matmat/MatMatProvider";
type Filter = "issues" | "notes" | "passed";

const slug = (s: string) => s.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
const displayTitle = (f: Finding, mode: Mode) => (mode === "beginner" ? PLAIN_TITLES[f.ruleId] ?? f.title : f.title);
const stagger = (i: number) => ({ ["--i" as string]: Math.min(i, 14) });

export function Report({ data, actions }: { data: ReportData; actions?: React.ReactNode }) {
  const { mode, setMode, setReport } = useMatMat();
  const [filter, setFilter] = useState<Filter>("issues");
  const [sev, setSev] = useState<Severity | "all">("all");
  const [fresh, setFresh] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const beginner = mode === "beginner";
  const LIMIT = 5;

  useEffect(() => {
    try { if (data.variant === "demo" || sessionStorage.getItem(`vibesec-fresh-${data.id}`) === "1") setFresh(true); } catch { /* bỏ qua */ }
  }, [data.id, data.variant]);
  const choose = (m: Mode) => setMode(m);

  const issues = useMemo(() => data.findings.filter((f) => f.status === "fail" && f.severity !== "info"), [data.findings]);
  const notes = useMemo(() => data.findings.filter((f) => f.status === "info" || f.status === "unknown" || (f.status === "fail" && f.severity === "info")), [data.findings]);
  const passed = useMemo(() => data.findings.filter((f) => f.status === "pass"), [data.findings]);
  useEffect(() => {
    setReport({ host: data.host, score: data.score, grade: data.grade, platforms: data.platforms, issues });
    return () => setReport(null);
  }, [data.host, data.score, data.grade, data.platforms, issues, setReport]);
  const summary = useMemo(() => buildSummary(data), [data]);
  const roadmap = useMemo(() => buildRoadmap(data.findings, data.score), [data.findings, data.score]);
  const base = filter === "issues" ? issues : filter === "notes" ? notes : passed;
  const filtered = filter === "issues" && sev !== "all" ? base.filter((f) => f.severity === sev) : base;
  const list = beginner && !showAll ? filtered.slice(0, LIMIT) : filtered;
  const hidden = filtered.length - list.length;
  function jumpTo(f: Finding) {
    setFilter("issues"); setSev("all"); setOpenId(f.fingerprint);
    setTimeout(() => document.getElementById(`f-${slug(f.fingerprint)}`)?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
  }
  const urgent = issues.filter((f) => f.severity === "critical" || f.severity === "high");
  const counts = SEVERITIES.filter((s) => s !== "info").map((s) => ({ s, n: data.severityCounts[s] ?? 0 }));
  const totalIssues = counts.reduce((a, c) => a + c.n, 0);

  function download() {
    const blob = new Blob([toMarkdown(data)], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `bao-cao-bao-mat-${data.host}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // Nội dung "engine" xuất ra ở khối terminal (dữ liệu thật, chỉ khác cách trình bày).
  const termLines: TermLine[] = useMemo(() => {
    const L: TermLine[] = [{ prefix: "$", text: `vibesec scan ${data.host}`, tone: "accent" }];
    L.push({ prefix: "✓", text: `${passed.length} kiểm tra đạt`, tone: "ok" });
    if (issues.length) {
      const worst = issues[0]!.severity;
      L.push({ prefix: "!", text: `${issues.length} vấn đề cần xử lý (${counts.filter((c) => c.n).map((c) => `${c.n} ${SEV_LABEL[c.s].toLowerCase()}`).join(", ")})`, tone: worst === "critical" || worst === "high" ? "crit" : "warn" });
      for (const f of issues.slice(0, 3)) L.push({ prefix: "→", text: `[${SEV_LABEL[f.severity].toUpperCase()}] ${f.title}`, tone: f.severity === "critical" || f.severity === "high" ? "crit" : "warn" });
    } else L.push({ prefix: "✓", text: "Không phát hiện vấn đề cần xử lý", tone: "ok" });
    L.push({ prefix: "=", text: `điểm ${data.score}/100 · hạng ${data.grade}`, tone: "accent" });
    return L;
  }, [data.host, data.score, data.grade, passed.length, issues, counts]);

  return (
    <div className="relative">
      {data.variant === "owner" && fresh && data.id && <FeedbackModal scanId={data.id} />}
      <div aria-hidden className="bg-grid pointer-events-none absolute inset-x-0 top-0 -z-10 h-72" />
      <div className="container-x py-10 sm:py-14">
        {data.variant === "demo" && (
          <p className="reveal mb-6 flex items-start gap-2.5 rounded-lg border border-accent/20 bg-accent-soft px-3.5 py-2.5 text-sm text-accent">
            <span className="chip-accent !px-1.5">DEMO</span>
            <span className="text-fg/80">Báo cáo này được tạo bằng cách chạy chính bộ luật quét thật của VibeSec trên một website mẫu — không có website thật nào được quét.</span>
          </p>
        )}

        {/* ---- đầu trang */}
        <header className="reveal flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <p className="eyebrow">báo cáo bảo mật <span aria-hidden>/</span> {formatDate(data.scannedAt)}{data.requestCount ? ` · ${data.requestCount} request` : ""}</p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight [overflow-wrap:anywhere] sm:text-4xl">{data.host}</h1>
            {data.platforms.length > 0 && <p className="mt-3 flex flex-wrap gap-1.5">{data.platforms.map((p) => <span key={p} className="chip-info">{p}</span>)}</p>}
          </div>
          <div className="flex flex-col gap-3 lg:items-end">
            <div role="group" aria-label="Mức chi tiết của báo cáo" className="inline-flex self-start rounded-lg border border-line-strong bg-surface p-0.5 text-[13px] lg:self-auto">
              {([["beginner", "Dễ hiểu"], ["technical", "Kỹ thuật"]] as const).map(([m, label]) => (
                <button key={m} onClick={() => choose(m)} aria-pressed={mode === m}
                  className={`h-8 rounded-md px-3.5 font-medium transition-colors ${mode === m ? "bg-white text-fg shadow-crisp" : "text-muted hover:text-fg"}`}>{label}</button>
              ))}
            </div>
            <div className="flex flex-wrap items-start gap-2">
              {actions}
              <button onClick={download} className="btn-ghost btn-sm">Tải báo cáo (.md)</button>
            </div>
          </div>
        </header>

        {/* ---- cảnh báo khẩn */}
        {!beginner && urgent.length > 0 && (
          <a href={`#f-${slug(urgent[0]!.fingerprint)}`} onClick={() => { setFilter("issues"); setSev("all"); }}
            className="reveal mt-8 flex items-center gap-3 rounded-xl border border-crit/25 bg-crit/5 px-4 py-3 text-sm transition-colors hover:bg-crit/10" style={stagger(1)} role="alert">
            <span className="live-dot !bg-crit" aria-hidden />
            <span className="min-w-0 flex-1"><strong className="font-semibold text-crit">{urgent.length} vấn đề mức Cao/Nghiêm trọng cần xử lý ngay.</strong> <span className="text-fg/80">{urgent[0]!.title}{urgent.length > 1 ? ` và ${urgent.length - 1} vấn đề khác` : ""}.</span></span>
            <span className="hidden text-xs font-medium text-crit sm:block">Xem chi tiết →</span>
          </a>
        )}

        {/* ---- chế độ Dễ hiểu: một màn hình duy nhất cho điểm + 3 việc làm trước */}
        {beginner && (
          <section className="reveal mt-8 rounded-2xl border border-line bg-white p-5 shadow-card sm:p-7" style={stagger(2)} aria-label="Tóm tắt">
            <div className="grid items-center gap-6 md:grid-cols-[auto_1fr] md:gap-10">
              <div className="mx-auto"><ScoreRing score={data.score} grade={data.grade} size={150} /></div>
              <div className="min-w-0">
                <MatMatSays text={`Mình xem giúp bạn rồi nè! ${plainScore(data.score, issues.length, urgent.length)}`} />
                {issues.length > 0 && (
                  <div className="mt-5">
                    <h2 className="text-[15px] font-semibold">{Math.min(3, issues.length)} việc nên làm trước</h2>
                    <ol className="mt-2 divide-y divide-line rounded-xl border border-line">
                      {issues.slice(0, 3).map((f, i) => (
                        <li key={f.fingerprint}>
                          <button onClick={() => jumpTo(f)} className="flex w-full items-center gap-3 px-3.5 py-2.5 text-left text-sm transition-colors hover:bg-surface">
                            <span className="mono grid size-6 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-accent">{i + 1}</span>
                            <span className="min-w-0 flex-1 leading-snug">{displayTitle(f, mode)}</span>
                            <span className={`${SEV_CHIP[f.severity]} hidden shrink-0 sm:inline-flex`}>{SEV_LABEL[f.severity]}</span>
                          </button>
                        </li>
                      ))}
                    </ol>
                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      <PromptButton text={buildAllPrompt(issues, data.host, data.platforms)} label={`Copy prompt cho AI (${Math.min(issues.length, 12)} vấn đề)`} big />
                      {data.canRescan && <RescanButton url={data.url} variant="ghost" label="Quét lại sau khi sửa" />}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* ---- điểm & phân bố */}
        {!beginner && <section className="reveal mt-10 grid items-center gap-10 lg:grid-cols-[auto_1fr] lg:gap-16" style={stagger(2)} aria-label="Điểm tổng thể">
          <ScoreRing score={data.score} grade={data.grade} />
          <div>
            <p className="mono mb-4 text-xs text-faint">Không website nào đạt 100: quét thụ động có điểm tối đa là 96 (90 nếu phạm vi quét bị hạn chế).</p>
            <h2 className="eyebrow">phân bố mức độ</h2>
            <div className="mt-3 flex h-2.5 w-full gap-0.5 overflow-hidden rounded-full bg-line" role="img" aria-label={`${totalIssues} vấn đề: ${counts.map((c) => `${c.n} ${SEV_LABEL[c.s]}`).join(", ")}`}>
              {totalIssues === 0 ? <div className="h-full w-full bg-ok" /> : counts.filter((c) => c.n).map((c) => <div key={c.s} className={`h-full ${SEV_BAR[c.s]} transition-[flex-grow] duration-700`} style={{ flexGrow: c.n }} />)}
            </div>
            <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-5">
              {counts.map(({ s, n }, i) => (
                <div key={s}>
                  <dt className="flex items-center gap-1.5 text-xs text-muted"><span className={`size-2 rounded-full ${n ? SEV_BAR[s] : "bg-line-strong"}`} />{SEV_LABEL[s]}</dt>
                  <dd className={`mt-0.5 text-3xl font-semibold ${n ? SEV_COLOR[s] : "text-faint"}`}><AnimatedNumber value={n} delay={i * 80} /></dd>
                </div>
              ))}
              <div>
                <dt className="flex items-center gap-1.5 text-xs text-muted"><span className="size-2 rounded-full bg-ok" />Đạt</dt>
                <dd className="mt-0.5 text-3xl font-semibold text-ok"><AnimatedNumber value={passed.length} delay={320} /></dd>
              </div>
            </dl>
            <p className="mt-6 max-w-2xl text-xs leading-relaxed text-faint">{data.disclaimer}</p>
          </div>
        </section>}

        {/* ---- terminal xuất kết quả */}
        {!beginner && <section className="reveal mt-10" style={stagger(3)} aria-label="Kết quả phân tích">
          <TermTyper lines={termLines} title="vibesec ~ kết-quả" storageKey={`vibesec-typed-${data.id ?? data.host}`} fresh={fresh} />
        </section>}

        {/* ---- tóm tắt & kế hoạch */}
        {!beginner && <section className="mt-14 grid gap-10 lg:grid-cols-[1fr_1.6fr]" aria-label="Tóm tắt và kế hoạch khắc phục">
          <div className="reveal" style={stagger(4)}>
            <h2 className="eyebrow">tóm tắt</h2>
            <div className="mt-3 space-y-2.5 text-[15px] leading-relaxed">
              {summary.map((p, i) => <p key={i} className={i === 0 ? "text-lg font-medium leading-snug text-fg" : "text-muted"}>{p}</p>)}
            </div>
          </div>
          {roadmap.length > 0 && (
            <div className="reveal" style={stagger(5)}>
              <h2 className="eyebrow">kế hoạch khắc phục</h2>
              <div className="mt-3 divide-y divide-line rounded-xl border border-line bg-white shadow-crisp">
                {roadmap.map((g) => (
                  <div key={g.effort} className="p-4">
                    <div className="flex items-baseline justify-between gap-3">
                      <h3 className="text-sm font-semibold">{EFFORT_LABEL[g.effort].title} <span className="font-normal text-muted">· {EFFORT_LABEL[g.effort].hint.toLowerCase()}</span></h3>
                      {g.gain > 0 && <span className="mono num shrink-0 text-xs font-medium text-ok">≈ +{g.gain} điểm</span>}
                    </div>
                    <ol className="mt-2.5 space-y-1.5 text-sm">
                      {g.items.map((f) => (
                        <li key={f.fingerprint}>
                          <a href={`#f-${slug(f.fingerprint)}`} onClick={() => { setFilter("issues"); setSev("all"); }} className="group flex items-start gap-2.5 rounded-md px-1 py-0.5 transition-colors hover:bg-surface">
                            <span className={`${SEV_CHIP[f.severity]} mt-0.5 shrink-0`}>{SEV_LABEL[f.severity]}</span>
                            <span className="min-w-0 text-muted transition-colors group-hover:text-fg">{displayTitle(f, mode)}</span>
                          </a>
                        </li>
                      ))}
                    </ol>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>}

        {/* ---- so sánh */}
        {data.comparison && (
          <section className="reveal mt-14" style={stagger(6)} aria-label="So sánh với lần quét trước">
            <h2 className="eyebrow">so với lần quét trước · {formatDate(data.comparison.previousAt)}</h2>
            <div className="mt-3 flex flex-wrap items-baseline gap-x-4 gap-y-1">
              <span className="num text-2xl text-faint">{data.comparison.previousScore}</span>
              <span aria-hidden className="text-faint">→</span>
              <span className={`num text-3xl font-semibold ${scoreColor(data.score)}`}>{data.score}</span>
              <span className={`chip ${data.comparison.scoreDelta > 0 ? "chip-ok" : data.comparison.scoreDelta < 0 ? "chip-high" : "chip-info"}`}>{data.comparison.scoreDelta > 0 ? "+" : ""}{data.comparison.scoreDelta} điểm</span>
            </div>
            <div className="mt-5 grid gap-6 text-sm sm:grid-cols-2">
              <DiffList title={`Đã khắc phục (${data.comparison.resolvedFindings.length})`} tone="ok" items={data.comparison.resolvedFindings} empty="Chưa có vấn đề nào được khắc phục từ lần quét trước." />
              <DiffList title={`Phát sinh mới (${data.comparison.newFindings.length})`} tone="risk" items={data.comparison.newFindings} empty="Không có vấn đề mới." />
            </div>
            <p className="mono mt-3 text-xs text-faint">{data.comparison.unchanged} vấn đề giữ nguyên</p>
          </section>
        )}

        {/* ---- điểm theo nhóm */}
        {!beginner && <section className="mt-14" aria-label="Điểm theo nhóm">
          <h2 className="eyebrow">điểm theo nhóm</h2>
          <ul className="mt-4 grid gap-x-10 gap-y-5 sm:grid-cols-2 lg:grid-cols-3">
            {CATEGORIES.map((c, i) => {
              const v = data.categoryScores[c];
              return (
                <li key={c} className="reveal" style={stagger(i)}>
                  <div className="mb-1.5 flex items-baseline justify-between text-sm">
                    <span>{CATEGORY_LABEL[c]}</span>
                    <span className={`mono text-[13px] font-medium ${v === null || v === undefined ? "text-faint" : scoreColor(v)}`}>{v === null || v === undefined ? "—" : <AnimatedNumber value={v} delay={i * 60} />}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={v ?? 0} aria-valuemin={0} aria-valuemax={100} aria-label={`Điểm nhóm ${CATEGORY_LABEL[c]}`}>
                    <div className={`h-full origin-left rounded-full transition-[width] duration-1000 ${v === null || v === undefined ? "" : v >= 80 ? "bg-ok" : v >= 60 ? "bg-med" : "bg-crit"}`} style={{ width: `${v ?? 0}%` }} />
                  </div>
                </li>
              );
            })}
          </ul>
        </section>}

        {/* ---- danh sách phát hiện */}
        <section className={beginner ? "mt-8" : "mt-16"} aria-label="Các phát hiện">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <h2 className="text-2xl font-semibold tracking-tight">Các phát hiện</h2>
            <div role="tablist" aria-label="Lọc theo loại" className="inline-flex rounded-lg border border-line-strong bg-surface p-0.5 text-[13px]">
              {([["issues", "Vấn đề", issues.length], ["notes", "Ghi chú", notes.length], ["passed", "Đạt", passed.length]] as const).map(([k, label, n]) => (
                <button key={k} role="tab" aria-selected={filter === k} onClick={() => { setFilter(k); setSev("all"); }}
                  className={`h-8 rounded-md px-3.5 font-medium transition-colors ${filter === k ? "bg-white text-fg shadow-crisp" : "text-muted hover:text-fg"}`}>{label} <span className="mono text-faint">{n}</span></button>
              ))}
            </div>
          </div>
          {filter === "issues" && issues.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-1.5" role="group" aria-label="Lọc theo mức độ">
              {(["all", "critical", "high", "medium", "low"] as const).map((s) => {
                const n = s === "all" ? issues.length : issues.filter((f) => f.severity === s).length;
                if (s !== "all" && n === 0) return null;
                return <button key={s} onClick={() => setSev(s)} aria-pressed={sev === s} className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${sev === s ? "border-fg bg-fg text-white" : "border-line-strong bg-white text-muted hover:border-fg/40 hover:text-fg"}`}>{s === "all" ? "Tất cả" : SEV_LABEL[s]} <span className="mono opacity-70">{n}</span></button>;
              })}
            </div>
          )}
          {list.length === 0 ? (
            <div className="mt-6 rounded-xl border border-dashed border-line-strong bg-surface px-6 py-14 text-center">
              <p className="pop mx-auto grid size-10 place-items-center rounded-full bg-ok/10 text-ok"><svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></p>
              <p className="mt-3 font-medium">{filter === "issues" ? "Các kiểm tra không phát hiện vấn đề nào" : "Chưa có mục nào"}</p>
              {filter === "issues" && <p className="mx-auto mt-1 max-w-md text-sm text-muted">Đây là tin tốt — nhưng hãy nhớ rằng chúng chỉ bao phủ những gì nhìn thấy được từ bên ngoài.</p>}
            </div>
          ) : (
            <ul className="mt-5 space-y-2.5">
              {list.map((f, i) => <FindingItem key={f.fingerprint} f={f} mode={mode} data={data} i={i} open={openId === f.fingerprint} onToggle={() => setOpenId((c) => (c === f.fingerprint ? null : f.fingerprint))} />)}
            </ul>
          )}
          {hidden > 0 && <button onClick={() => setShowAll(true)} className="btn-ghost mt-4 w-full">Xem thêm {hidden} mục</button>}
          {beginner && showAll && filtered.length > LIMIT && <button onClick={() => setShowAll(false)} className="btn-ghost mt-4 w-full">Thu gọn</button>}
        </section>

        {/* ---- chi tiết kỹ thuật */}
        {mode === "technical" && (
          <section className="mt-16" aria-label="Chi tiết kỹ thuật">
            <h2 className="text-2xl font-semibold tracking-tight">Chi tiết kỹ thuật</h2>
            <p className="mt-2 text-sm text-muted">{data.platforms.length > 0 ? <>Nền tảng nhận diện được (dùng để chọn đoạn cấu hình gợi ý): <span className="mono text-fg">{data.platforms.join(", ")}</span></> : "Không nhận diện được chắc chắn nền tảng hosting nào, nên chỉ gợi ý giá trị header chung chung."}</p>
            {(data.targets ?? []).length === 0 && data.variant === "shared" && <p className="mt-3 text-sm text-muted">Header phản hồi gốc chỉ hiển thị cho chủ báo cáo.</p>}
            <div className="mt-4 space-y-2.5">
              {(data.targets ?? []).filter((t) => t.role !== "script").map((t, i) => (
                <details key={i} className="group panel overflow-hidden">
                  <summary className="flex items-center gap-3 px-4 py-3 text-sm transition-colors hover:bg-surface">
                    <Chevron />
                    <span className="chip-info">{t.role}</span>
                    <span className="mono min-w-0 flex-1 truncate text-[13px]">{t.final_url ?? t.url}</span>
                    <span className="mono num text-xs text-muted">{t.status_code ?? t.error_code ?? "—"}</span>
                  </summary>
                  <div className="space-y-3 border-t border-line px-4 py-4">
                    {t.tls && <p className="mono text-xs text-muted">TLS: {t.tls.protocol} · {t.tls.cipher} · nhà cấp: {t.tls.issuer ?? "?"}{t.tls.keyType ? ` · khoá ${t.tls.keyType.toUpperCase()}${t.tls.keyBits ? ` ${t.tls.keyBits}` : ""}` : ""} · hiệu lực đến {t.tls.validTo ?? "?"}</p>}
                    <CodeBlock lines={t.headers ? Object.entries(t.headers).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map((x) => `${k}: ${x}`)) : ["(không ghi nhận header)"]} />
                  </div>
                </details>
              ))}
            </div>
          </section>
        )}

        {beginner && <p className="mt-10 max-w-2xl text-xs leading-relaxed text-faint">{data.disclaimer}</p>}

        {/* ---- cách tính điểm */}
        <section className="mt-16 border-t border-line pt-8" aria-label="Cách tính điểm">
          <details className="group">
            <summary className="flex items-center gap-2 text-sm font-medium text-muted transition-colors hover:text-fg"><Chevron />Điểm được tính như thế nào?</summary>
            <div className="mt-4 max-w-3xl space-y-3 text-sm leading-relaxed text-muted">
              <p>Mỗi website bắt đầu với 100 điểm. Mỗi vấn đề “Có vấn đề” bị trừ <strong className="font-medium text-fg">trọng số mức độ × hệ số độ tin cậy</strong>. Kết quả Đạt, Ghi chú hay “chưa kiểm tra được” không bao giờ làm giảm điểm.</p>
              <ul className="flex flex-wrap gap-x-6 gap-y-1.5">
                {scoringTable().map((r) => <li key={r.severity}><span className={`${SEV_COLOR[r.severity]} font-medium`}>{r.label}</span>: <span className="mono num text-fg">−{r.weight}</span></li>)}
                <li>Độ tin cậy: cao <span className="mono num text-fg">×{CONFIDENCE_FACTOR.high}</span> · {CONFIDENCE_LABEL.medium} <span className="mono num text-fg">×{CONFIDENCE_FACTOR.medium}</span> · thấp <span className="mono num text-fg">×{CONFIDENCE_FACTOR.low}</span></li>
              </ul>
              <p>Để một lỗi nặng không bị che bởi nhiều mục nhỏ đạt, có trần điểm: có vấn đề <em>Nghiêm trọng</em> thì tối đa 59 điểm; có vấn đề <em>Cao</em> thì tối đa 79 điểm. Hạng: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, còn lại F.</p>
            </div>
          </details>
        </section>
      </div>
    </div>
  );
}

const Chevron = () => <svg viewBox="0 0 24 24" className="size-4 shrink-0 text-faint transition-transform duration-200 group-open:rotate-90" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg>;

function DiffList({ title, items, tone, empty }: { title: string; items: Finding[]; tone: "ok" | "risk"; empty: string }) {
  return (
    <div>
      <h3 className={`font-medium ${tone === "ok" ? "text-ok" : "text-high"}`}>{title}</h3>
      {items.length === 0 ? <p className="mt-1.5 text-muted">{empty}</p> : (
        <ul className="mt-2 space-y-1.5">{items.slice(0, 8).map((f) => <li key={f.fingerprint} className="flex items-start gap-2 text-muted"><span className={`${SEV_CHIP[f.severity]} mt-0.5 shrink-0`}>{SEV_LABEL[f.severity]}</span><span>{f.title}</span></li>)}</ul>
      )}
    </div>
  );
}

/** Khối mã có đánh số dòng. Nội dung luôn được React escape (không dùng innerHTML) nên dữ liệu lấy từ website đích không thể chèn mã. */
function CodeBlock({ lines, copy }: { lines: string[]; copy?: string }) {
  return (
    <div className="group relative overflow-hidden rounded-lg border border-line bg-surface">
      {copy && <div className="absolute right-2 top-2 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"><CopyButton text={copy} /></div>}
      <pre className="overflow-x-auto py-3 text-[12.5px] leading-6">
        {lines.map((l, i) => (
          <div key={i} className="flex px-3 transition-colors hover:bg-raised/60">
            <span className="mr-4 w-5 shrink-0 select-none text-right text-faint" aria-hidden>{i + 1}</span>
            <code className="whitespace-pre-wrap break-all text-fg/90">{l || " "}</code>
          </div>
        ))}
      </pre>
    </div>
  );
}

function Confidence({ level }: { level: Finding["confidence"] }) {
  const n = level === "high" ? 3 : level === "medium" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-2" title={`Độ tin cậy ${CONFIDENCE_LABEL[level]}`}>
      <span className="flex gap-0.5" aria-hidden>{[1, 2, 3].map((i) => <span key={i} className={`h-3 w-1.5 rounded-sm ${i <= n ? "bg-accent" : "bg-line-strong"}`} />)}</span>
      <span className="text-xs text-muted">{CONFIDENCE_LABEL[level]}</span>
    </span>
  );
}

function FindingItem({ f, mode, data, i, open, onToggle }: { f: Finding; mode: Mode; data: ReportData; i: number; open: boolean; onToggle: () => void }) {
  const isPass = f.status === "pass";
  const isFail = f.status === "fail";
  const [opened, setOpened] = useState(false);
  useEffect(() => { if (open) setOpened(true); }, [open]);
  const fy = mode === "beginner" ? FEYNMAN[f.ruleId] : undefined;
  const simpleText = fy
    ? isFail ? `Mình giải thích nhé! ${fy.like}\n\nViệc bạn cần làm: ${fy.todo}` : `${isPass ? "Chỗ này ổn rồi nha! " : "Chỉ để bạn biết: "}${fy.like}`
    : `Mình tóm tắt nhé: ${f.summary}`;
  const { askMatMat } = useMatMat();
  const glossary = mode === "beginner" ? glossaryFor(f.title, f.summary, f.remediation?.summary ?? "") : [];
  const effort = isFail ? EFFORT_LABEL[effortFor(f)] : null;
  const owasp = OWASP_MAP[f.ruleId];
  const component = f.affectedUrl ? (() => { try { const u = new URL(f.affectedUrl); return u.pathname === "/" ? u.host : u.host + u.pathname; } catch { return f.affectedUrl; } })() : CATEGORY_LABEL[f.category];
  const rail = isFail ? SEV_RAIL[f.severity] : isPass ? "border-l-ok/50" : "border-l-line-strong";
  const steps = f.remediation?.steps ?? [];
  const fixText = f.remediation ? [f.remediation.summary, ...steps.map((s, k) => `${k + 1}. ${s}`)].join("\n") : "";

  return (
    <li id={`f-${slug(f.fingerprint)}`} className="reveal scroll-mt-24" style={stagger(i)}>
      <details open={open} className={`group panel border-l-[3px] ${rail} transition-shadow open:shadow-pop`}>
        <summary onClick={(e) => { e.preventDefault(); onToggle(); }} className="flex items-start gap-3 px-4 py-3.5 transition-colors hover:bg-surface/70 sm:items-center">
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              {isFail ? <span className={SEV_CHIP[f.severity]}>{SEV_LABEL[f.severity]}</span> : isPass ? <span className="chip-ok">Đạt</span> : <span className="chip-info">{f.status === "unknown" ? "Chưa kiểm tra được" : "Ghi chú"}</span>}
              <span className="font-medium leading-snug">{displayTitle(f, mode)}</span>
            </span>
            <span className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted">
              <span>{CATEGORY_LABEL[f.category]}</span>
              <span className="mono max-w-full truncate text-faint">{component}</span>
              {effort && <span className="hidden sm:inline">· {effort.title.toLowerCase()}</span>}
              {mode === "technical" && <span className="mono text-faint">· {f.ruleId}</span>}
            </span>
          </span>
          <span className="hidden shrink-0 sm:block"><Confidence level={f.confidence} /></span>
          <Chevron />
        </summary>

        {mode === "beginner" && (
          <div className="border-t border-line px-4 py-5">
            <MatMatSays active={opened} text={simpleText}>
              <div className="flex flex-wrap items-center gap-2">
                {isFail && <PromptButton text={buildFixPrompt(f, data.host, data.platforms)} />}
                <button type="button" onClick={() => askMatMat(`Giải thích ${PLAIN_TITLES[f.ruleId] ?? f.title}`)} className="btn-ghost btn-sm">🐾 Hỏi thêm Mật Mật</button>
              </div>
              {isFail && <p className="mt-2.5 text-[13px] text-muted">Bấm “Copy prompt cho AI” rồi dán vào Cursor hoặc Claude Code, nó sẽ tự tìm chỗ cần sửa giúp bạn. Sửa xong thì quét lại nhé.</p>}
            </MatMatSays>
          </div>
        )}
        <Fold on={mode === "beginner"}>
        <div className="grid gap-x-8 gap-y-6 border-t border-line px-4 py-5 md:grid-cols-2">
          <div className="min-w-0 space-y-5">
            {fy && (
              <div className="rounded-xl border border-accent/20 bg-accent-soft/60 px-4 py-3.5">
                <p className="eyebrow !text-accent">hình dung đơn giản</p>
                <p className="mt-1.5 text-[15px] leading-relaxed">{fy.like}</p>
                {isFail && <p className="mt-2 text-xs text-muted">Mức độ: {PLAIN_SEV[f.severity]}</p>}
              </div>
            )}
            <Section title={mode === "beginner" ? "Chuyện gì đang xảy ra" : "Chúng tôi phát hiện"}><p className="text-[15px] leading-relaxed">{f.summary}</p></Section>
            <Section title={mode === "beginner" ? "Vì sao nên quan tâm" : "Tác động tiềm ẩn"}><p className="text-[15px] leading-relaxed text-muted">{f.explanation}</p></Section>
            {glossary.length > 0 && (
              <div className="space-y-1.5 rounded-lg border border-accent/15 bg-accent-soft/60 px-3.5 py-3 text-sm">
                {glossary.map((g) => <p key={g.term}><strong className="font-medium text-fg">{g.term}:</strong> <span className="text-muted">{g.meaning}</span></p>)}
              </div>
            )}
            {f.evidence.length > 0 && (
              <Section title="Bằng chứng">
                <CodeBlock lines={f.evidence} />
              </Section>
            )}
            {mode === "technical" && f.technical && <Section title="Chi tiết kỹ thuật"><p className="mono whitespace-pre-wrap text-xs leading-relaxed text-muted">{f.technical}</p></Section>}
          </div>

          <div className="min-w-0 space-y-5">
            <Section title="Thành phần bị ảnh hưởng">
              <p className="mono break-all text-[13px]">{f.affectedUrl ?? CATEGORY_LABEL[f.category]}</p>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5"><Confidence level={f.confidence} />{mode === "technical" && owasp && <span className="text-xs text-muted">{owasp.join(" · ")}</span>}</div>
            </Section>

            {f.remediation && !isPass && (
              <>
                <Section title={mode === "beginner" ? "Bạn cần làm gì" : "Cách khắc phục"}>
                  {fy && <p className="mb-3 rounded-lg bg-surface px-3.5 py-2.5 text-[15px] leading-relaxed">{fy.todo}</p>}
                  <div className="mb-3 flex flex-wrap gap-2">
                    <PromptButton text={buildFixPrompt(f, data.host, data.platforms)} />
                    <button type="button" onClick={() => askMatMat(`Giải thích ${PLAIN_TITLES[f.ruleId] ?? f.title}`)} className="btn-ghost btn-sm">🐾 Hỏi Mật Mật</button>
                  </div>
                  {mode === "technical" || !fy ? <div className="term">
                    <div className="term-body whitespace-pre-wrap break-words text-[13px] leading-6">
                      <span className="prompt" aria-hidden>→ </span>
                      <Typed text={fixText} play={opened} cps={260} />
                    </div>
                  </div> : <details className="text-sm"><summary className="cursor-pointer text-accent hover:underline">Xem các bước chi tiết</summary><div className="term mt-2"><div className="term-body whitespace-pre-wrap break-words text-[13px] leading-6">{fixText}</div></div></details>}
                  {effort && <p className="mt-2 text-xs text-faint">Ước lượng công sức: {effort.title} — {effort.hint.toLowerCase()}.</p>}
                </Section>
                {f.remediation.snippets.length > 0 && (
                  <Section title={mode === "beginner" ? "Đưa đoạn này cho người làm web (hoặc dán vào cài đặt hosting)" : "Lệnh và cấu hình để dán"}>
                    <div className="space-y-3">
                      {f.remediation.snippets.map((s, k) => (
                        <div key={k}>
                          <p className="mb-1.5 text-xs text-muted">{s.label}</p>
                          <CodeBlock lines={s.code.split("\n")} copy={s.code} />
                        </div>
                      ))}
                    </div>
                    {f.remediation.platformUnknown && <p className="mt-2 text-xs text-muted">Chúng tôi không nhận diện được hệ thống hosting của bạn, nên liệt kê các lựa chọn phổ biến: hãy chọn đúng mục bạn đang dùng.</p>}
                  </Section>
                )}
                <Section title="Quét lại sau khi sửa">
                  <p className="mb-3 text-sm text-muted">Triển khai thay đổi, đợi khoảng một phút cho bộ nhớ đệm hết hiệu lực, rồi quét lại để xác nhận vấn đề đã được giải quyết.</p>
                  {data.canRescan ? <RescanButton url={data.url} variant="ghost" label="Quét lại website này" /> : <p className="text-xs text-faint">Hãy đăng nhập bằng tài khoản chủ báo cáo để quét lại.</p>}
                </Section>
              </>
            )}
            {mode === "technical" && f.references.length > 0 && (
              <Section title="Tài liệu tham khảo">
                <ul className="space-y-1 text-sm">{f.references.map((r) => <li key={r.url}><a className="break-all text-accent underline-offset-2 hover:underline" href={r.url} target="_blank" rel="noopener noreferrer">{r.title}</a></li>)}</ul>
              </Section>
            )}
          </div>
        </div>
        </Fold>
      </details>
    </li>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="eyebrow mb-2">{title}</h3>
      {children}
    </div>
  );
}

/**
 * Prompt dán vào công cụ AI viết code (Cursor, Claude Code…): hiện sẵn nội dung ngay phía trên nút Copy để người dùng đọc và kiểm tra
 * trước khi dán. Phần tử nằm trong hàng flex-wrap nên `basis-full` đẩy nút xuống dòng dưới.
 */
function PromptButton({ text, label = "Copy prompt cho AI", big = false }: { text: string; label?: string; big?: boolean }) {
  const [ok, setOk] = useState(false);
  return (
    <>
      <pre tabIndex={0} aria-label="Nội dung prompt" className="mono max-h-56 w-full basis-full overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-surface p-3 text-[12.5px] leading-6 text-fg/90">{text}</pre>
      <button type="button" className={`btn-primary ${big ? "" : "btn-sm"}`} onClick={async () => { try { await navigator.clipboard.writeText(text); setOk(true); setTimeout(() => setOk(false), 2000); } catch { /* clipboard bị chặn */ } }}>
        {ok ? "Đã copy prompt ✓" : label}
      </button>
    </>
  );
}

/** Ở chế độ Dễ hiểu, phần kỹ thuật được gấp lại để người mới không bị ngợp. */
function Fold({ on, children }: { on: boolean; children: React.ReactNode }) {
  if (!on) return <>{children}</>;
  return (
    <details className="border-t border-line">
      <summary className="cursor-pointer px-4 py-3 text-[13px] text-muted hover:text-fg">▸ Xem chi tiết kỹ thuật (không bắt buộc)</summary>
      {children}
    </details>
  );
}
