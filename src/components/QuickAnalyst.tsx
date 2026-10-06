"use client";

import { useState } from "react";
import { CopyButton } from "./CopyButton";

/** Các thành phần góc nhìn analyst cho kết quả quét nhanh: nguồn gốc lỗi, hậu quả, tái hiện, phân loại ưu tiên, xuất dữ liệu. */
export type Urgency = "now" | "week" | "later";
export interface ATech {
  ruleId: string; severity: string; confidence: string; evidence: string[]; owasp: string[]; fixSummary: string;
  impact?: { today: string; worst: string; who: string; urgency: Urgency };
  statement?: string; sub?: string; origin?: { kind: string; label: string; meaning: string; rootCause: string }; repro?: string | null;
  references?: { title: string; url: string }[];
}
export interface AItem { id: string; label: string; status: "pass" | "warning" | "fail"; text: string; tech?: ATech }

export const URGENCY: Record<Urgency, { label: string; cls: string }> = { now: { label: "Xử lý ngay hôm nay", cls: "chip-crit" }, week: { label: "Xử lý trong tuần này", cls: "chip-med" }, later: { label: "Xử lý khi rảnh", cls: "chip-info" } };
const SEV: Record<string, string> = { critical: "nghiêm trọng", high: "cao", medium: "trung bình", low: "thấp", info: "thông tin" };
const CONF: Record<string, string> = { high: "cao", medium: "vừa", low: "thấp" };
const ORIGIN_CLS: Record<string, string> = { absent: "chip-info", misconfigured: "chip-med", lapse: "chip-high", exposure: "chip-crit" };

/** Tiêu đề một mục ở dạng KHẲNG ĐỊNH: đọc lướt là hiểu issue ngay. Mục đã đạt dùng câu tóm tắt của luật. */
export function headline(i: AItem): { title: string; sub: string } {
  if (i.status !== "pass" && i.tech?.statement) return { title: i.tech.statement, sub: i.tech.sub ?? i.text };
  return { title: i.label, sub: i.text };
}

/** Khối bên cột "Vấn đề": câu khẳng định, nguồn gốc, hậu quả, bằng chứng, tái hiện, phân loại. */
export function ProblemPane({ item }: { item: AItem }) {
  const t = item.tech;
  const h = headline(item);
  return (
    <>
      <p className="eyebrow">vấn đề · {item.label}</p>
      <h3 className="mt-2 text-[17px] font-semibold leading-snug">{h.title}</h3>
      <p className="mt-1.5 text-[15px] leading-relaxed text-muted">{h.sub}</p>
      {item.status !== "pass" && t?.origin && (
        <div className="mt-4 rounded-xl border border-line p-3.5">
          <div className="flex flex-wrap items-center gap-2"><p className="eyebrow">nguồn gốc</p><span className={`${ORIGIN_CLS[t.origin.kind] ?? "chip-info"} !normal-case`}>{t.origin.label}</span></div>
          <p className="mt-2 text-sm leading-relaxed">{t.origin.meaning}</p>
          <p className="mt-1.5 text-sm leading-relaxed text-muted"><span className="font-medium text-fg">Quy trình đang thiếu:</span> {t.origin.rootCause}</p>
        </div>
      )}
      {t?.impact && (
        <div className="mt-3 rounded-xl border border-line bg-surface p-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2"><p className="eyebrow">hậu quả nếu chưa xử lý</p><span className={`${URGENCY[t.impact.urgency].cls} !normal-case`}>{URGENCY[t.impact.urgency].label}</span></div>
          <dl className="mt-2 space-y-2 text-sm leading-relaxed">
            <div><dt className="text-xs font-medium text-faint">Trong 1 ngày</dt><dd>{t.impact.today}</dd></div>
            <div><dt className="text-xs font-medium text-faint">Trường hợp xấu nhất</dt><dd>{t.impact.worst}</dd></div>
            <div><dt className="text-xs font-medium text-faint">Ai khai thác được</dt><dd>{t.impact.who}</dd></div>
          </dl>
        </div>
      )}
      {t && <p className="mono mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-faint"><span>{t.ruleId}</span><span>mức: {SEV[t.severity] ?? t.severity}</span><span>tin cậy: {CONF[t.confidence] ?? t.confidence}</span></p>}
      {t && t.evidence.length > 0 && <div className="mt-3"><p className="eyebrow mb-1.5">bằng chứng</p><pre className="mono max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-surface p-3 text-[12px] leading-5">{t.evidence.join("\n")}</pre></div>}
      {item.status !== "pass" && t?.repro && (
        <div className="mt-3">
          <div className="mb-1.5 flex items-center justify-between gap-2"><p className="eyebrow">tự tái hiện (chỉ đọc)</p><CopyButton text={t.repro} /></div>
          <pre className="mono max-h-28 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-white p-3 text-[12px] leading-5">{t.repro}</pre>
        </div>
      )}
      {t && t.owasp.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{t.owasp.map((o) => <span key={o} className="chip-info !normal-case">{o}</span>)}</div>}
    </>
  );
}

/** Phân loại ưu tiên: bao nhiêu mục cần xử lý hôm nay / tuần này / khi rảnh, và phân bố theo nguồn gốc lỗi. */
export function TriageStrip({ items }: { items: AItem[] }) {
  const bad = items.filter((i) => i.status !== "pass" && i.tech);
  if (bad.length === 0) return null;
  const by = <K extends string>(f: (i: AItem) => K | undefined) => bad.reduce<Record<string, number>>((m, i) => { const k = f(i); if (k) m[k] = (m[k] ?? 0) + 1; return m; }, {});
  const urg = by((i) => i.tech?.impact?.urgency);
  const org = by((i) => i.tech?.origin?.kind);
  const ORG_LABEL: Record<string, string> = { absent: "Chưa triển khai", misconfigured: "Cấu hình sai hoặc yếu", lapse: "Bỏ sót bảo trì", exposure: "Lộ do sơ suất" };
  return (
    <div className="grid gap-3 border-b border-line bg-white px-4 py-3 text-sm sm:grid-cols-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5"><span className="eyebrow">ưu tiên</span>
        {(["now", "week", "later"] as const).map((u) => <span key={u} className={`${URGENCY[u].cls} !normal-case`}>{urg[u] ?? 0} {URGENCY[u].label.toLowerCase()}</span>)}</div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5"><span className="eyebrow">nguồn gốc</span>
        {Object.keys(ORG_LABEL).filter((k) => org[k]).map((k) => <span key={k} className={`${ORIGIN_CLS[k]} !normal-case`}>{org[k]} {ORG_LABEL[k]!.toLowerCase()}</span>)}</div>
    </div>
  );
}

function toMarkdown(host: string, score: number, grade: string, items: AItem[]): string {
  const L: string[] = [`# Kết quả quét nhanh — ${host}`, "", `Điểm: **${score}/100** (hạng ${grade}). Quét thụ động, chỉ trang chủ.`, ""];
  const bad = items.filter((i) => i.status !== "pass");
  L.push(`## Phát hiện cần xử lý (${bad.length})`, "");
  bad.forEach((i, n) => {
    const t = i.tech, h = headline(i);
    L.push(`### ${n + 1}. ${h.title}`, "", h.sub, "");
    L.push(`- Mục: ${i.label} · Mức: ${SEV[t?.severity ?? ""] ?? t?.severity ?? "—"} · Tin cậy: ${CONF[t?.confidence ?? ""] ?? "—"}${t?.impact ? ` · ${URGENCY[t.impact.urgency].label}` : ""}`);
    if (t?.origin) L.push(`- Nguồn gốc: ${t.origin.label} — ${t.origin.rootCause}`);
    if (t?.impact) L.push(`- Trong 1 ngày: ${t.impact.today}`, `- Xấu nhất: ${t.impact.worst}`, `- Ai khai thác: ${t.impact.who}`);
    if (t?.owasp.length) L.push(`- OWASP: ${t.owasp.join("; ")}`);
    if (t?.evidence.length) L.push("", "Bằng chứng:", "```", ...t.evidence, "```");
    if (t?.repro) L.push("", "Tái hiện:", "```bash", t.repro, "```");
    if (t?.fixSummary) L.push("", `Giải pháp: ${t.fixSummary}`);
    L.push("");
  });
  const ok = items.filter((i) => i.status === "pass");
  L.push(`## Đạt (${ok.length})`, "", ...ok.map((i) => `- ${i.label}: ${i.text}`), "");
  return L.join("\n");
}

function download(name: string, mime: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Xuất dữ liệu để analyst đưa vào quy trình riêng: JSON (nguyên bản kết quả) hoặc Markdown (dán vào ticket). */
export function ExportButtons({ result }: { result: { host: string; score: number; grade: string; items: AItem[] } }) {
  const [copied, setCopied] = useState(false);
  const stamp = new Date().toISOString().slice(0, 10);
  return (
    <div className="flex flex-wrap gap-2">
      <button type="button" className="btn-ghost btn-sm" onClick={() => download(`vibesec-${result.host}-${stamp}.json`, "application/json", JSON.stringify(result, null, 2))}>Tải JSON</button>
      <button type="button" className="btn-ghost btn-sm" onClick={async () => { try { await navigator.clipboard.writeText(toMarkdown(result.host, result.score, result.grade, result.items)); setCopied(true); setTimeout(() => setCopied(false), 1800); } catch { /* clipboard bị chặn */ } }}>{copied ? "Đã chép ✓" : "Chép Markdown"}</button>
    </div>
  );
}
