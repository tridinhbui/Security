"use client";

import { useEffect, useRef, useState } from "react";
import { Typed } from "../motion/Typed";
import { Face } from "./MatMat";

/**
 * Mật Mật "nói" một đoạn văn bản bằng hiệu ứng gõ chữ, bắt đầu khi khối hiện vào màn hình (hoặc khi `active`).
 * Dùng khắp nơi để giải thích. Văn bản viết sẵn, không dùng AI.
 */
export function MatMatSays({ text, active = true, cps = 90, className = "", children }: { text: string; active?: boolean; cps?: number; className?: string; children?: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [seen, setSeen] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    if (typeof IntersectionObserver === "undefined") { setSeen(true); return; }
    const io = new IntersectionObserver(([e]) => { if (e?.isIntersecting) { setSeen(true); io.disconnect(); } }, { threshold: 0.3 });
    io.observe(el);
    return () => io.disconnect();
  }, [seen]);

  // Gõ lại mỗi lần được kích hoạt lại (ví dụ mở lại một mục đã đóng); đóng lại thì ẩn nút để lần sau hiện đúng lúc gõ xong.
  useEffect(() => { setDone(false); }, [text, active]);

  return (
    <div ref={ref} className={`flex items-start gap-3 ${className}`}>
      <Face className="mt-0.5 size-9 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="whitespace-pre-wrap break-words rounded-2xl rounded-tl-sm border border-accent/20 bg-accent-soft/70 px-4 py-3 text-[15.5px] leading-[1.7] text-fg">
          <Typed text={text} play={active && seen} cps={cps} onDone={() => setDone(true)} />
        </div>
        {done && children && <div className="fade-in mt-3">{children}</div>}
        {!children ? null : !done && <div className="mt-3 h-9" aria-hidden />}
      </div>
    </div>
  );
}
