"use client";

import { CopyButton } from "./CopyButton";

/** Hiển thị giải thích theo từng trường hợp cụ thể (xem src/lib/scanner/explain.ts). Dùng chung cho quét nhanh và báo cáo đầy đủ. */
export type Role = "dev" | "host" | "dns" | "owner";
export interface ExplainData {
  saw: string; why: string; consequence: string;
  steps: { who: Role; text: string }[]; expect: string;
  notes: { line: string; note: string }[];
  certainty?: "confirmed" | "potential" | "inconclusive";
  caveat?: string;
  verify?: string;
}
const CERTAINTY: Record<NonNullable<ExplainData["certainty"]>, { label: string; cls: string }> = {
  confirmed: { label: "Đã xác nhận được", cls: "text-ok" },
  potential: { label: "Rủi ro tiềm năng", cls: "text-med" },
  inconclusive: { label: "Chưa đủ dữ liệu để kết luận", cls: "text-muted" },
};
export const ROLE_LABEL: Record<Role, string> = { dev: "Lập trình viên", host: "Quản trị hosting / CDN", dns: "Quản lý tên miền (DNS)", owner: "Chủ website" };

/** Ba câu trả lời: thấy gì, vì sao là vấn đề, hệ quả với website này. */
export function ExplainSections({ e }: { e: ExplainData }) {
  const rows: [string, string][] = [["Chúng tôi thấy", e.saw], ["Vì sao đây là vấn đề", e.why], ["Với website của bạn", e.consequence]];
  return (
    <dl className="space-y-3">
      {rows.filter(([, v]) => v).map(([k, v]) => (
        <div key={k}><dt className="eyebrow">{k}</dt><dd className="mt-1 text-[15px] leading-relaxed">{v}</dd></div>
      ))}
      {e.certainty && (
        <div>
          <dt className="eyebrow">Mức chắc chắn</dt>
          <dd className="mt-1 text-sm leading-relaxed"><span className={`font-medium ${CERTAINTY[e.certainty].cls}`}>{CERTAINTY[e.certainty].label}.</span>{e.caveat ? <span className="text-muted"> {e.caveat}</span> : null}</dd>
        </div>
      )}
    </dl>
  );
}

/** Các bước: ai làm gì; cuối cùng là "kết quả đúng trông thế nào". */
export function StepsView({ steps, expect, verify }: { steps: ExplainData["steps"]; expect: string; verify?: string }) {
  return (
    <div>
      <ol className="space-y-2.5">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
            <span className="mono mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">{i + 1}</span>
            <span className="min-w-0"><span className="chip-info mr-2 !normal-case align-middle">{ROLE_LABEL[s.who]}</span>{s.text}</span>
          </li>
        ))}
      </ol>
      {expect && <p className="mt-3 rounded-lg border border-ok/25 bg-ok/5 px-3 py-2 text-sm leading-relaxed"><span className="font-medium text-ok">Sửa đúng thì: </span>{expect}</p>}
      {verify && <p className="mt-2 text-[13px] text-muted">Tự kiểm tra lại: <code className="mono break-all text-[12px]">{verify}</code></p>}
    </div>
  );
}

/** Từng dòng bằng chứng kèm lời đọc: "dòng này nghĩa là gì và vì sao nó chứng minh vấn đề". Có nút hỏi chatbot về đúng dòng đó. */
export function EvidenceNotes({ notes, onAsk }: { notes: ExplainData["notes"]; onAsk?: (line: string) => void }) {
  if (notes.length === 0) return null;
  return (
    <ul className="space-y-2">
      {notes.map((n, i) => (
        <li key={i} className="rounded-lg border border-line bg-surface p-2.5">
          <div className="flex items-start gap-2">
            <code className="mono min-w-0 flex-1 whitespace-pre-wrap break-words text-[12px] leading-5">{n.line}</code>
            <span className="flex shrink-0 gap-1.5">
              <CopyButton text={n.line} />
              {onAsk && <button type="button" onClick={() => onAsk(n.line)} className="inline-flex h-7 items-center rounded-md border border-line-strong bg-white px-2 text-[11px] font-medium text-accent shadow-crisp hover:border-accent/50">Hỏi dòng này</button>}
            </span>
          </div>
          <p className="mt-1.5 flex gap-1.5 text-[13px] leading-snug text-muted"><span aria-hidden className="text-faint">→</span><span>{n.note}</span></p>
        </li>
      ))}
    </ul>
  );
}
