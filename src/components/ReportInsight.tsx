"use client";

import { ANALYST, originFor, reproFor, type OriginKind } from "@/lib/scanner/analyst";
import { IMPACT, URGENCY_LABEL, urgencyFor, type Urgency } from "@/lib/scanner/impact";
import type { Finding } from "@/lib/scanner/types";
import { CopyButton } from "./CopyButton";

/** Góc nhìn analyst cho báo cáo đầy đủ: câu khẳng định, nguồn gốc lỗi, hậu quả, lệnh tái hiện, phân loại ưu tiên, xuất JSON. */
const URGENCY_CLS: Record<Urgency, string> = { now: "chip-crit", week: "chip-med", later: "chip-info" };
const ORIGIN_CLS: Record<OriginKind, string> = { absent: "chip-info", misconfigured: "chip-med", lapse: "chip-high", exposure: "chip-crit" };
const ORIGIN_LABEL: Record<OriginKind, string> = { absent: "Chưa triển khai", misconfigured: "Cấu hình sai hoặc yếu", lapse: "Bỏ sót bảo trì", exposure: "Lộ do sơ suất" };

/** Câu khẳng định + câu phụ của một phát hiện đang lỗi (null nếu luật chưa có mô tả). */
export function statementOf(f: Finding): { title: string; sub: string } | null {
  if (f.status !== "fail") return null;
  const a = ANALYST[f.ruleId];
  return a ? { title: a.statement, sub: a.sub } : null;
}

/** Nguồn gốc lỗi + hậu quả nếu chưa xử lý (hai khối cạnh nhau trên màn hình rộng). */
export function Insight({ f }: { f: Finding }) {
  if (f.status !== "fail") return null;
  const origin = ANALYST[f.ruleId] ? originFor(f.ruleId, f.title) : null;
  const impact = IMPACT[f.ruleId];
  if (!origin && !impact) return null;
  const urgency = urgencyFor(f.ruleId, f.severity);
  return (
    <div className="grid gap-3 border-t border-line px-4 py-4 md:grid-cols-2">
      {origin && (
        <div className="rounded-xl border border-line p-3.5">
          <div className="flex flex-wrap items-center gap-2"><p className="eyebrow">nguồn gốc</p><span className={`${ORIGIN_CLS[origin.kind]} !normal-case`}>{origin.label}</span></div>
          <p className="mt-2 text-sm leading-relaxed">{origin.meaning}</p>
          <p className="mt-1.5 text-sm leading-relaxed text-muted"><span className="font-medium text-fg">Quy trình đang thiếu:</span> {origin.rootCause}</p>
        </div>
      )}
      {impact && (
        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2"><p className="eyebrow">hậu quả nếu chưa xử lý</p><span className={`${URGENCY_CLS[urgency]} !normal-case`}>{URGENCY_LABEL[urgency]}</span></div>
          <dl className="mt-2 space-y-2 text-sm leading-relaxed">
            <div><dt className="text-xs font-medium text-faint">Trong 1 ngày</dt><dd>{impact.today}</dd></div>
            <div><dt className="text-xs font-medium text-faint">Trường hợp xấu nhất</dt><dd>{impact.worst}</dd></div>
            <div><dt className="text-xs font-medium text-faint">Ai khai thác được</dt><dd>{impact.who}</dd></div>
          </dl>
        </div>
      )}
    </div>
  );
}

/** Lệnh chỉ-đọc để analyst tự tái hiện phát hiện. */
export function Repro({ f, host }: { f: Finding; host: string }) {
  if (f.status !== "fail") return null;
  const cmd = reproFor(f.ruleId, host);
  if (!cmd) return null;
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-2"><h4 className="eyebrow">tự tái hiện (chỉ đọc)</h4><CopyButton text={cmd} /></div>
      <pre className="mono overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-white p-3 text-[12px] leading-5">{cmd}</pre>
    </div>
  );
}

/** Dải phân loại ưu tiên: bao nhiêu mục cần xử lý hôm nay / tuần này / khi rảnh, và phân bố theo nguồn gốc lỗi. */
export function ReportTriage({ findings }: { findings: Finding[] }) {
  const bad = findings.filter((f) => f.status === "fail" && f.severity !== "info");
  if (bad.length === 0) return null;
  const urg: Record<string, number> = {}, org: Record<string, number> = {};
  for (const f of bad) {
    const u = urgencyFor(f.ruleId, f.severity); urg[u] = (urg[u] ?? 0) + 1;
    if (ANALYST[f.ruleId]) { const k = originFor(f.ruleId, f.title).kind; org[k] = (org[k] ?? 0) + 1; }
  }
  return (
    <div className="mt-4 grid gap-3 rounded-xl border border-line bg-white p-3.5 text-sm sm:grid-cols-2" aria-label="Phân loại ưu tiên">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5"><span className="eyebrow">ưu tiên</span>
        {(["now", "week", "later"] as const).map((u) => <span key={u} className={`${URGENCY_CLS[u]} !normal-case`}>{urg[u] ?? 0} {URGENCY_LABEL[u].toLowerCase()}</span>)}</div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5"><span className="eyebrow">nguồn gốc</span>
        {(Object.keys(ORIGIN_LABEL) as OriginKind[]).filter((k) => org[k]).map((k) => <span key={k} className={`${ORIGIN_CLS[k]} !normal-case`}>{org[k]} {ORIGIN_LABEL[k].toLowerCase()}</span>)}</div>
    </div>
  );
}

/** Tải JSON có cấu trúc (kèm góc nhìn analyst) để đưa vào công cụ hay quy trình riêng. */
export function ReportJson({ data }: { data: { host: string; url: string; scannedAt: string; score: number; grade: string; categoryScores: unknown; findings: Finding[] } }) {
  function download() {
    const out = {
      host: data.host, url: data.url, scannedAt: data.scannedAt, score: data.score, grade: data.grade, categoryScores: data.categoryScores,
      findings: data.findings.map((f) => {
        const a = ANALYST[f.ruleId];
        return {
          ruleId: f.ruleId, title: f.title, status: f.status, severity: f.severity, confidence: f.confidence, affectedUrl: f.affectedUrl, summary: f.summary, evidence: f.evidence,
          ...(f.status === "fail" && a ? { statement: a.statement, sub: a.sub, origin: originFor(f.ruleId, f.title).kind, urgency: urgencyFor(f.ruleId, f.severity), impact: IMPACT[f.ruleId] ?? null, repro: reproFor(f.ruleId, data.host) } : {}),
          references: f.references, fix: f.remediation ? { summary: f.remediation.summary, steps: f.remediation.steps ?? [], snippets: f.remediation.snippets } : null,
        };
      }),
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(out, null, 2)], { type: "application/json" }));
    const el = document.createElement("a");
    el.href = url; el.download = `vibesec-${data.host}-${data.scannedAt.slice(0, 10)}.json`; document.body.appendChild(el); el.click(); el.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <button type="button" className="btn-ghost btn-sm" onClick={download}>Tải JSON</button>;
}
