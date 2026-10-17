"use client";

import { CopyButton } from "./CopyButton";
import { KIND_LABEL, PLATFORM_LABEL, type DeepDive } from "@/lib/scanner/deep-dive";

/** Tầng 2 “Đào sâu kỹ thuật” (xem src/lib/scanner/deep-dive.ts). Mặc định thu gọn để không làm người mới choáng. */
function Code({ code }: { code: string }) {
  return (
    <div className="group relative overflow-hidden rounded-lg border border-line bg-surface">
      <div className="absolute right-2 top-2 transition-opacity sm:opacity-0 sm:group-hover:opacity-100 sm:group-focus-within:opacity-100"><CopyButton text={code} /></div>
      <pre className="overflow-x-auto px-3 py-2.5 text-[12.5px] leading-6"><code className="whitespace-pre text-fg/90">{code}</code></pre>
    </div>
  );
}

const H = ({ children }: { children: React.ReactNode }) => <h4 className="eyebrow mb-1.5">{children}</h4>;

export function DeepDiveView({ d, defaultOpen = false }: { d: DeepDive; defaultOpen?: boolean }) {
  const kind = KIND_LABEL[d.kind];
  return (
    <details open={defaultOpen} className="rounded-xl border border-line bg-white">
      <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium text-accent hover:underline">Đào sâu kỹ thuật: cơ chế, cấu hình theo nền tảng, lỗi thường gặp</summary>
      <div className="space-y-5 border-t border-line px-4 py-4 text-sm leading-relaxed">
        <div>
          <H>Phân loại</H>
          <p><span className="font-medium">{kind.label}.</span> <span className="text-muted">{kind.hint}</span></p>
        </div>
        <div><H>Cơ chế</H><p>{d.mechanism}</p></div>
        {d.exchange && (
          <div className="grid gap-3 md:grid-cols-2">
            <div><H>Trước khi sửa</H><Code code={d.exchange.before} /></div>
            <div><H>Sau khi sửa</H><Code code={d.exchange.after} /></div>
          </div>
        )}
        <div>
          <H>Cấu hình theo nền tảng</H>
          <div className="space-y-3">
            {d.frameworks.map((s, i) => (
              <div key={i}>
                <p className="mb-1.5 text-xs text-muted"><span className="chip-info mr-2 !normal-case">{PLATFORM_LABEL[s.platform]}</span>{s.label}</p>
                <Code code={s.code} />
              </div>
            ))}
          </div>
        </div>
        <div><H>Lỗi thường gặp khi sửa</H><ul className="list-disc space-y-1.5 pl-5">{d.mistakes.map((m, i) => <li key={i}>{m}</li>)}</ul></div>
        <div><H>Đánh đổi và tương thích</H><ul className="list-disc space-y-1.5 pl-5">{d.tradeoffs.map((m, i) => <li key={i}>{m}</li>)}</ul></div>
        <div><H>Cách tự kiểm chứng (chỉ đọc)</H><div className="space-y-1.5">{d.verify.map((v, i) => <Code key={i} code={v} />)}</div></div>
        <div><H>Nguồn</H><ul className="space-y-1">{d.sources.map((s) => <li key={s.url}><a className="break-all text-accent underline-offset-2 hover:underline" href={s.url} target="_blank" rel="noopener noreferrer">{s.title}</a></li>)}</ul></div>
      </div>
    </details>
  );
}
