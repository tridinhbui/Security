"use client";
import { useMatMat } from "./MatMatProvider";

/** Công tắc chế độ toàn site: "Dễ hiểu" (giải thích kiểu Feynman) hoặc "Kỹ thuật". */
export function ModeToggle() {
  const { mode, setMode } = useMatMat();
  return (
    <div role="group" aria-label="Chế độ hiển thị" className="hidden rounded-full border border-line-strong bg-surface p-0.5 text-[12.5px] md:inline-flex">
      {([["beginner", "Dễ hiểu"], ["technical", "Kỹ thuật"]] as const).map(([m, label]) => (
        <button key={m} onClick={() => setMode(m)} aria-pressed={mode === m}
          className={`h-8 rounded-full px-3 font-medium transition-colors ${mode === m ? "bg-white text-fg shadow-crisp" : "text-muted hover:text-fg"}`}>{label}</button>
      ))}
    </div>
  );
}
