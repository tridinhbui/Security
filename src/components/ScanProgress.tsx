"use client";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { PROGRESS_STEPS, type ScanStatus } from "@/lib/db-types";

export function ScanProgress({ scanId, initialStatus, url }: { scanId: string; initialStatus: ScanStatus; url: string }) {
  const router = useRouter();
  const [status, setStatus] = useState<ScanStatus>(initialStatus);
  const [stale, setStale] = useState(false);

  useEffect(() => {
    let stop = false;
    let ticks = 0;
    const poll = async () => {
      if (stop) return;
      try {
        const res = await fetch(`/api/scans/${scanId}`, { cache: "no-store" });
        if (res.ok) {
          const s = (await res.json()) as { status: ScanStatus };
          setStatus(s.status);
          if (s.status === "completed" || s.status === "failed") return router.refresh();
        }
      } catch { /* transient; keep polling */ }
      ticks++;
      if (ticks > 60) setStale(true);
      setTimeout(poll, ticks < 10 ? 1200 : 2500);
    };
    void poll();
    return () => { stop = true; };
  }, [scanId, router]);

  const idx = PROGRESS_STEPS.findIndex((s) => s.status === status);
  return (
    <div className="mx-auto max-w-xl px-5 py-16" aria-live="polite">
      <p className="text-sm text-muted">Đang quét</p>
      <h1 className="text-2xl font-semibold tracking-tight break-all mt-1">{url}</h1>
      <ol className="mt-10 space-y-3">
        {PROGRESS_STEPS.map((s, i) => {
          const state = i < idx ? "done" : i === idx ? "active" : "todo";
          return (
            <li key={s.status} className="flex items-center gap-3 text-[15px]">
              <span className={`size-2 rounded-full ${state === "done" ? "bg-ok" : state === "active" ? "bg-fg animate-pulse" : "bg-line-strong"}`} />
              <span className={state === "todo" ? "text-faint" : state === "active" ? "text-fg" : "text-muted"}>{s.label}</span>
            </li>
          );
        })}
      </ol>
      <p className="mt-10 text-sm text-muted">Thường mất 10–30 giây. Bạn có thể rời khỏi trang này, báo cáo sẽ nằm trong lịch sử quét của bạn.</p>
      {stale && <p className="mt-3 text-sm text-med">Lần này lâu hơn bình thường. Hệ thống xử lý có thể đang bận, nhưng lượt quét vẫn sẽ hoàn tất.</p>}
    </div>
  );
}
