"use client";
import { useEffect, useRef } from "react";

/**
 * Hộp thoại xác nhận dùng <dialog> gốc: trình duyệt tự khoá focus bên trong, Esc đóng, nền mờ.
 * Thay cho window.confirm để đồng bộ giao diện và dùng được với trình đọc màn hình.
 */
export function ConfirmDialog({ open, title, description, confirmLabel, danger = false, busy = false, onConfirm, onCancel }: {
  open: boolean; title: string; description: string; confirmLabel: string; danger?: boolean; busy?: boolean; onConfirm: () => void; onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className="confirm" aria-labelledby="confirm-title" aria-describedby="confirm-desc" onCancel={(e) => { e.preventDefault(); onCancel(); }} onClick={(e) => { if (e.target === ref.current) onCancel(); }}>
      <div className="w-[26rem] max-w-full rounded-2xl border border-line bg-white p-6 shadow-pop">
        <div className={`mb-4 grid size-10 place-items-center rounded-full ${danger ? "bg-crit/10 text-crit" : "bg-accent-soft text-accent"}`} aria-hidden>
          <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">{danger ? <><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></> : <><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.01" /></>}</svg>
        </div>
        <h2 id="confirm-title" className="text-lg font-semibold tracking-tight">{title}</h2>
        <p id="confirm-desc" className="mt-1.5 text-sm leading-relaxed text-muted">{description}</p>
        <div className="mt-6 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="btn-ghost" autoFocus>Huỷ</button>
          <button type="button" onClick={onConfirm} disabled={busy} className={danger ? "btn bg-crit text-white shadow-crisp hover:bg-[#a81f15]" : "btn-primary"}>{busy ? "Đang xử lý…" : confirmLabel}</button>
        </div>
      </div>
    </dialog>
  );
}
