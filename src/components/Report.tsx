"use client";

import { useEffect, useMemo, useState } from "react";
import { glossaryFor, PLAIN_TITLES } from "@/lib/beginner";
import type { TargetView } from "@/lib/db-types";
import { formatDate, gradeColor, scoreColor, SEV_COLOR, SEV_DOT } from "@/lib/format";
import { buildRoadmap, buildSummary, EFFORT_LABEL, effortFor, OWASP_MAP, scoringTable, toMarkdown, CONFIDENCE_FACTOR } from "@/lib/guidance";
import { CATEGORY_LABEL, CONFIDENCE_LABEL, SEV_LABEL } from "@/lib/i18n";
import { CATEGORIES, SEVERITIES, type Finding, type Severity } from "@/lib/scanner/types";
import { CopyButton } from "./CopyButton";
import { RescanButton } from "./RescanButton";

export interface ReportData {
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
  /** "demo" hiện banner giới thiệu. */
  variant?: "owner" | "shared" | "demo";
  disclaimer: string;
}

type Mode = "beginner" | "technical";
type Filter = "issues" | "notes" | "passed";

export function Report({ data, actions }: { data: ReportData; actions?: React.ReactNode }) {
  const [mode, setMode] = useState<Mode>("beginner");
  const [filter, setFilter] = useState<Filter>("issues");

  useEffect(() => {
    try { const m = localStorage.getItem("vibesec-mode"); if (m === "technical" || m === "beginner") setMode(m); } catch { /* không đọc được localStorage */ }
  }, []);
  const choose = (m: Mode) => { setMode(m); try { localStorage.setItem("vibesec-mode", m); } catch { /* bỏ qua */ } };

  const issues = useMemo(() => data.findings.filter((f) => f.status === "fail" && f.severity !== "info"), [data.findings]);
  const notes = useMemo(() => data.findings.filter((f) => f.status === "info" || f.status === "unknown" || (f.status === "fail" && f.severity === "info")), [data.findings]);
  const passed = useMemo(() => data.findings.filter((f) => f.status === "pass"), [data.findings]);
  const list = filter === "issues" ? issues : filter === "notes" ? notes : passed;
  const summary = useMemo(() => buildSummary(data), [data]);
  const roadmap = useMemo(() => buildRoadmap(data.findings, data.score), [data.findings, data.score]);
  const failCounts = SEVERITIES.filter((s) => s !== "info").map((s) => ({ s, n: data.severityCounts[s] ?? 0 }));

  function download() {
    const blob = new Blob([toMarkdown(data)], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `bao-cao-bao-mat-${data.host}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="mx-auto max-w-5xl px-5 py-10">
      {data.variant === "demo" && (
        <p className="mb-6 text-sm border-l-2 border-line-strong pl-3 text-muted">
          <strong className="text-fg font-medium">Báo cáo demo.</strong> Được tạo bằng cách chạy chính bộ luật quét thật của VibeSec trên một website mẫu — không có website thật nào được quét.
        </p>
      )}

      {/* ---- đầu trang */}
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <p className="text-sm text-muted">Báo cáo bảo mật</p>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight break-all">{data.host}</h1>
          <p className="text-sm text-muted mt-1 num">{formatDate(data.scannedAt)}{data.requestCount ? ` · ${data.requestCount} request` : ""}</p>
        </div>
        <div className="flex flex-col gap-3 lg:items-end">
          <div role="group" aria-label="Mức chi tiết của báo cáo" className="inline-flex rounded-md border border-line-strong p-0.5 text-sm self-start lg:self-auto">
            {([["beginner", "Chế độ dễ hiểu"], ["technical", "Chế độ kỹ thuật"]] as const).map(([m, label]) => (
              <button key={m} onClick={() => choose(m)} aria-pressed={mode === m}
                className={`px-3 h-8 rounded ${mode === m ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>{label}</button>
            ))}
          </div>
          <div className="flex flex-wrap gap-2 items-start">
            {actions}
            <button onClick={download} className="h-9 px-3 rounded-md border border-line-strong text-sm hover:border-fg/50">Tải báo cáo (.md)</button>
          </div>
        </div>
      </div>

      {/* ---- điểm số */}
      <section className="mt-10 grid gap-10 lg:grid-cols-[auto_1fr] lg:gap-16 items-start" aria-label="Điểm tổng thể">
        <div className="flex items-end gap-5">
          <div className={`num text-8xl font-semibold leading-none tracking-tighter ${scoreColor(data.score)}`}>{data.score}</div>
          <div className="pb-2">
            <div className={`text-5xl font-semibold leading-none ${gradeColor(data.grade)}`} aria-label={`Hạng ${data.grade}`}>{data.grade}</div>
            <div className="text-xs text-muted mt-2 uppercase tracking-wider">trên 100 điểm</div>
          </div>
        </div>
        <div>
          <dl className="flex flex-wrap gap-x-8 gap-y-3">
            {failCounts.map(({ s, n }) => (
              <div key={s} className="flex items-baseline gap-2">
                <dt className="flex items-center gap-1.5 text-sm text-muted"><span className={`size-2 rounded-full ${n ? SEV_DOT[s] : "bg-line-strong"}`} />{SEV_LABEL[s]}</dt>
                <dd className={`num text-xl font-semibold ${n ? SEV_COLOR[s] : "text-faint"}`}>{n}</dd>
              </div>
            ))}
            <div className="flex items-baseline gap-2">
              <dt className="flex items-center gap-1.5 text-sm text-muted"><span className="size-2 rounded-full bg-ok" />Đạt</dt>
              <dd className="num text-xl font-semibold text-ok">{passed.length}</dd>
            </div>
          </dl>
          <p className="mt-5 text-sm text-muted max-w-2xl">{data.disclaimer}</p>
        </div>
      </section>

      {/* ---- tóm tắt */}
      <section className="mt-10 border-t border-line pt-6" aria-label="Tóm tắt">
        <h2 className="text-sm font-medium text-muted">Tóm tắt</h2>
        <div className="mt-3 space-y-2 max-w-3xl text-[15px] leading-relaxed">
          {summary.map((p, i) => <p key={i} className={i === 0 ? "text-fg text-lg" : "text-muted"}>{p}</p>)}
        </div>
      </section>

      {/* ---- kế hoạch khắc phục */}
      {roadmap.length > 0 && (
        <section className="mt-10 border-t border-line pt-6" aria-label="Kế hoạch khắc phục">
          <h2 className="text-sm font-medium text-muted">Kế hoạch khắc phục — nên làm theo thứ tự này</h2>
          <div className="mt-4 grid gap-8 md:grid-cols-3">
            {roadmap.map((g) => (
              <div key={g.effort}>
                <div className="flex items-baseline justify-between gap-2">
                  <h3 className="font-medium">{EFFORT_LABEL[g.effort].title}</h3>
                  {g.gain > 0 && <span className="text-xs text-ok num">≈ +{g.gain} điểm</span>}
                </div>
                <p className="text-xs text-muted mt-0.5">{EFFORT_LABEL[g.effort].hint}</p>
                <ol className="mt-3 space-y-2 text-sm">
                  {g.items.map((f) => (
                    <li key={f.fingerprint}>
                      <a href={`#f-${slug(f.fingerprint)}`} onClick={() => setFilter("issues")} className="flex gap-2 hover:text-fg text-muted">
                        <span className={`shrink-0 text-xs font-semibold uppercase mt-0.5 w-20 ${SEV_COLOR[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
                        <span className="min-w-0">{displayTitle(f, mode)}</span>
                      </a>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ---- so sánh */}
      {data.comparison && (
        <section className="mt-10 border-t border-line pt-6" aria-label="So sánh với lần quét trước">
          <h2 className="text-sm font-medium text-muted">So sánh với lần quét trước <span className="num">({formatDate(data.comparison.previousAt)})</span></h2>
          <p className="mt-2 text-lg">
            <span className="num text-muted">{data.comparison.previousScore}</span> → <span className={`num font-semibold ${scoreColor(data.score)}`}>{data.score}</span>{" "}
            <span className={`num text-sm ${data.comparison.scoreDelta > 0 ? "text-ok" : data.comparison.scoreDelta < 0 ? "text-high" : "text-muted"}`}>
              ({data.comparison.scoreDelta > 0 ? "+" : ""}{data.comparison.scoreDelta})
            </span>
          </p>
          <div className="mt-4 grid sm:grid-cols-2 gap-6 text-sm">
            <DiffList title={`Đã khắc phục (${data.comparison.resolvedFindings.length})`} tone="ok" items={data.comparison.resolvedFindings} empty="Chưa có vấn đề nào được khắc phục từ lần quét trước." />
            <DiffList title={`Phát sinh mới (${data.comparison.newFindings.length})`} tone="risk" items={data.comparison.newFindings} empty="Không có vấn đề mới." />
          </div>
          <p className="mt-3 text-xs text-muted num">{data.comparison.unchanged} vấn đề giữ nguyên.</p>
        </section>
      )}

      {/* ---- điểm theo nhóm */}
      <section className="mt-10 border-t border-line pt-6" aria-label="Điểm theo nhóm">
        <h2 className="text-sm font-medium text-muted">Điểm theo nhóm</h2>
        <ul className="mt-4 grid gap-x-12 gap-y-4 sm:grid-cols-2">
          {CATEGORIES.map((c) => {
            const v = data.categoryScores[c];
            return (
              <li key={c}>
                <div className="flex justify-between text-sm mb-1.5">
                  <span>{CATEGORY_LABEL[c]}</span>
                  <span className={`num ${v === null || v === undefined ? "text-faint" : scoreColor(v)}`}>{v ?? "—"}</span>
                </div>
                <div className="h-1 rounded bg-line" role="progressbar" aria-valuenow={v ?? 0} aria-valuemin={0} aria-valuemax={100} aria-label={`Điểm nhóm ${CATEGORY_LABEL[c]}`}>
                  <div className={`h-1 rounded ${v === null || v === undefined ? "" : v >= 80 ? "bg-ok" : v >= 60 ? "bg-med" : "bg-crit"}`} style={{ width: `${v ?? 0}%` }} />
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      {/* ---- danh sách phát hiện */}
      <section className="mt-12 border-t border-line pt-6" aria-label="Các phát hiện">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Các phát hiện</h2>
          <div role="tablist" className="flex gap-1 text-sm">
            {([["issues", "Vấn đề", issues.length], ["notes", "Ghi chú", notes.length], ["passed", "Đạt", passed.length]] as const).map(([k, label, n]) => (
              <button key={k} role="tab" aria-selected={filter === k} onClick={() => setFilter(k)}
                className={`px-3 h-8 rounded ${filter === k ? "bg-raised text-fg" : "text-muted hover:text-fg"}`}>{label} <span className="num text-faint">{n}</span></button>
            ))}
          </div>
        </div>
        {list.length === 0 ? (
          <p className="py-10 text-muted text-sm">{filter === "issues" ? "Các kiểm tra không phát hiện vấn đề nào. Đây là tin tốt — nhưng hãy nhớ rằng chúng chỉ bao phủ những gì nhìn thấy được từ bên ngoài." : "Chưa có mục nào."}</p>
        ) : (
          <ul className="mt-4 divide-y divide-line border-y border-line">
            {list.map((f) => <FindingItem key={f.fingerprint} f={f} mode={mode} data={data} />)}
          </ul>
        )}
      </section>

      {/* ---- chi tiết kỹ thuật */}
      {mode === "technical" && (
        <section className="mt-12 border-t border-line pt-6" aria-label="Chi tiết kỹ thuật">
          <h2 className="text-lg font-semibold tracking-tight">Chi tiết kỹ thuật</h2>
          {data.platforms.length > 0 && <p className="mt-2 text-sm text-muted">Nền tảng được nhận diện (dùng để chọn đoạn cấu hình gợi ý): <span className="text-fg">{data.platforms.join(", ")}</span></p>}
          {data.platforms.length === 0 && <p className="mt-2 text-sm text-muted">Không nhận diện được chắc chắn nền tảng hosting nào, nên chỉ gợi ý giá trị header chung chung.</p>}
          {(data.targets ?? []).length === 0 && data.variant === "shared" && <p className="mt-3 text-sm text-muted">Header phản hồi gốc chỉ hiển thị cho chủ báo cáo.</p>}
          <div className="mt-4 space-y-3">
            {(data.targets ?? []).filter((t) => t.role !== "script").map((t, i) => (
              <details key={i} className="group border border-line rounded-md">
                <summary className="px-3 py-2.5 flex items-center gap-3 text-sm">
                  <span className="text-faint group-open:rotate-90 transition-transform">▸</span>
                  <span className="font-mono text-xs text-muted">{t.role}</span>
                  <span className="truncate flex-1">{t.final_url ?? t.url}</span>
                  <span className="num text-muted">{t.status_code ?? t.error_code ?? "—"}</span>
                </summary>
                <div className="px-3 pb-3 space-y-3">
                  {t.tls && <p className="text-xs text-muted font-mono">TLS: {t.tls.protocol} · {t.tls.cipher} · nhà cấp: {t.tls.issuer ?? "?"}{t.tls.keyType ? ` · khoá ${t.tls.keyType.toUpperCase()}${t.tls.keyBits ? ` ${t.tls.keyBits}` : ""}` : ""} · hiệu lực đến {t.tls.validTo ?? "?"}</p>}
                  <pre className="text-xs font-mono text-muted overflow-x-auto bg-surface rounded p-3 leading-relaxed">
                    {t.headers ? Object.entries(t.headers).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map((x) => `${k}: ${x}`)).join("\n") : "(không ghi nhận header)"}
                  </pre>
                </div>
              </details>
            ))}
          </div>
        </section>
      )}

      {/* ---- cách tính điểm */}
      <section className="mt-12 border-t border-line pt-6" aria-label="Cách tính điểm">
        <details className="group">
          <summary className="flex items-center gap-2 text-sm font-medium text-muted hover:text-fg"><span className="group-open:rotate-90 transition-transform">▸</span>Điểm được tính như thế nào?</summary>
          <div className="mt-4 text-sm text-muted space-y-3 max-w-3xl">
            <p>Mỗi website bắt đầu với 100 điểm. Mỗi vấn đề “Có vấn đề” bị trừ <strong className="text-fg font-medium">trọng số mức độ × hệ số độ tin cậy</strong>. Kết quả Đạt, Ghi chú hay “chưa kiểm tra được” không bao giờ làm giảm điểm.</p>
            <ul className="flex flex-wrap gap-x-6 gap-y-1">
              {scoringTable().map((r) => <li key={r.severity}><span className={SEV_COLOR[r.severity]}>{r.label}</span>: <span className="num text-fg">−{r.weight}</span></li>)}
              <li>Độ tin cậy: cao <span className="num text-fg">×{CONFIDENCE_FACTOR.high}</span> · {CONFIDENCE_LABEL.medium} <span className="num text-fg">×{CONFIDENCE_FACTOR.medium}</span> · thấp <span className="num text-fg">×{CONFIDENCE_FACTOR.low}</span></li>
            </ul>
            <p>Để một lỗi nặng không bị che bởi nhiều mục nhỏ đạt, có trần điểm: có vấn đề <em>Nghiêm trọng</em> thì tối đa 59 điểm; có vấn đề <em>Cao</em> thì tối đa 79 điểm. Hạng: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, còn lại F.</p>
          </div>
        </details>
      </section>
    </div>
  );
}

function DiffList({ title, items, tone, empty }: { title: string; items: Finding[]; tone: "ok" | "risk"; empty: string }) {
  return (
    <div>
      <h3 className={`font-medium ${tone === "ok" ? "text-ok" : "text-high"}`}>{title}</h3>
      {items.length === 0 ? <p className="text-muted mt-1">{empty}</p> : (
        <ul className="mt-1 space-y-1">{items.slice(0, 8).map((f) => <li key={f.fingerprint} className="text-muted"><span className={SEV_COLOR[f.severity]}>{SEV_LABEL[f.severity]}</span> · {f.title}</li>)}</ul>
      )}
    </div>
  );
}

const slug = (s: string) => s.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
const displayTitle = (f: Finding, mode: Mode) => (mode === "beginner" ? PLAIN_TITLES[f.ruleId] ?? f.title : f.title);

function FindingItem({ f, mode, data }: { f: Finding; mode: Mode; data: ReportData }) {
  const isPass = f.status === "pass";
  const isFail = f.status === "fail";
  const glossary = mode === "beginner" ? glossaryFor(f.title, f.summary, f.remediation?.summary ?? "") : [];
  const effort = isFail ? EFFORT_LABEL[effortFor(f)] : null;
  const owasp = OWASP_MAP[f.ruleId];
  return (
    <li id={`f-${slug(f.fingerprint)}`} className="scroll-mt-20">
      <details className="group">
        <summary className="flex items-start gap-3 py-4 hover:bg-surface -mx-2 px-2 rounded">
          <span className="mt-2 shrink-0">
            {isPass ? <span className="block size-2 rounded-full bg-ok" aria-label="Đạt" /> : <span className={`block size-2 rounded-full ${f.status === "unknown" ? "bg-line-strong" : SEV_DOT[f.severity]}`} aria-hidden />}
          </span>
          <span className="flex-1 min-w-0">
            <span className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
              {isFail && <span className={`text-xs font-semibold uppercase tracking-wide ${SEV_COLOR[f.severity]}`}>{SEV_LABEL[f.severity]}</span>}
              {isPass && <span className="text-xs font-semibold uppercase tracking-wide text-ok">Đạt</span>}
              {!isPass && !isFail && <span className="text-xs font-semibold uppercase tracking-wide text-info">{f.status === "unknown" ? "Chưa kiểm tra được" : "Ghi chú"}</span>}
              <span className="font-medium">{displayTitle(f, mode)}</span>
            </span>
            <span className="block text-sm text-muted mt-0.5">
              {CATEGORY_LABEL[f.category]}
              {effort && <> · {effort.title.toLowerCase()}</>}
              {mode === "technical" && <> · <span className="font-mono text-xs">{f.ruleId}</span> · độ tin cậy {CONFIDENCE_LABEL[f.confidence]}</>}
            </span>
          </span>
          <span className="text-faint mt-1 group-open:rotate-90 transition-transform" aria-hidden>▸</span>
        </summary>

        <div className="pb-6 pl-5 sm:pl-6 space-y-5 text-[15px] leading-relaxed">
          <Section title="Chúng tôi phát hiện"><p>{f.summary}</p></Section>
          <Section title="Vì sao quan trọng"><p className="text-muted">{f.explanation}</p></Section>
          {glossary.length > 0 && (
            <div className="text-sm border-l-2 border-line-strong pl-3 space-y-1">
              {glossary.map((g) => <p key={g.term}><strong className="font-medium text-fg">{g.term}:</strong> <span className="text-muted">{g.meaning}</span></p>)}
            </div>
          )}
          {f.evidence.length > 0 && (
            <Section title="Bằng chứng">
              <pre className="text-xs font-mono bg-surface rounded p-3 overflow-x-auto whitespace-pre-wrap break-all text-muted leading-relaxed">{f.evidence.join("\n")}</pre>
              {mode === "technical" && f.affectedUrl && <p className="mt-2 text-xs text-muted font-mono break-all">URL bị ảnh hưởng: {f.affectedUrl}</p>}
            </Section>
          )}
          {mode === "technical" && f.technical && <Section title="Chi tiết kỹ thuật"><p className="text-sm text-muted font-mono whitespace-pre-wrap">{f.technical}</p></Section>}
          {mode === "technical" && owasp && <Section title="Ánh xạ OWASP Top 10"><p className="text-sm text-muted">{owasp.join(" · ")}</p></Section>}

          {f.remediation && !isPass && (
            <>
              <Section title="Cách khắc phục">
                <p>{f.remediation.summary}</p>
                {f.remediation.steps && <ul className="mt-2 list-disc pl-5 space-y-1 text-muted">{f.remediation.steps.map((s, i) => <li key={i}>{s}</li>)}</ul>}
                {effort && <p className="mt-2 text-xs text-faint">Ước lượng công sức: {effort.title} — {effort.hint.toLowerCase()}.</p>}
              </Section>
              {f.remediation.snippets.length > 0 && (
                <Section title="Ví dụ cấu hình">
                  <div className="space-y-3">
                    {f.remediation.snippets.map((s, i) => (
                      <div key={i}>
                        <div className="flex items-center justify-between gap-3 mb-1.5">
                          <span className="text-xs text-muted">{s.label}</span>
                          <CopyButton text={s.code} />
                        </div>
                        <pre className="text-xs font-mono bg-surface border border-line rounded p-3 overflow-x-auto leading-relaxed">{s.code}</pre>
                      </div>
                    ))}
                  </div>
                  {f.remediation.platformUnknown && <p className="mt-2 text-xs text-muted">Chúng tôi không nhận diện được hệ thống hosting của bạn, nên chỉ hiển thị chính header — không đoán file cấu hình.</p>}
                </Section>
              )}
              <Section title="Quét lại sau khi sửa">
                <p className="text-sm text-muted mb-3">Triển khai thay đổi, đợi khoảng một phút cho bộ nhớ đệm hết hiệu lực, rồi quét lại để xác nhận vấn đề này đã được giải quyết.</p>
                {data.canRescan ? <RescanButton url={data.url} variant="ghost" label="Quét lại website này" /> : <p className="text-xs text-faint">Hãy đăng nhập bằng tài khoản chủ báo cáo để quét lại.</p>}
              </Section>
            </>
          )}
          {mode === "technical" && f.references.length > 0 && (
            <Section title="Tài liệu tham khảo">
              <ul className="space-y-1 text-sm">{f.references.map((r) => <li key={r.url}><a className="text-muted hover:text-fg underline underline-offset-2 break-all" href={r.url} target="_blank" rel="noopener noreferrer">{r.title}</a></li>)}</ul>
            </Section>
          )}
        </div>
      </details>
    </li>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-faint mb-1.5">{title}</h3>
      {children}
    </div>
  );
}
