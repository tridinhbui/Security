"use client";

import { useEffect, useState } from "react";
import { Typed } from "../motion/Typed";
import { Face } from "./MatMat";

const FACES = [["😣", "Rất khó hiểu"], ["😕", "Hơi khó"], ["🙂", "Tạm được"], ["😀", "Dễ hiểu"], ["🤩", "Tuyệt vời"]] as const;
const TAGS = [["easy", "Dễ hiểu"], ["confusing", "Có chỗ khó hiểu"], ["missing-guide", "Thiếu hướng dẫn"], ["hard-commands", "Lệnh khó dán"], ["slow", "Quét hơi lâu"], ["great", "Muốn thêm tính năng"]] as const;

/**
 * Popup giữa màn hình: Mật Mật hỏi feedback ngay sau khi quét xong. BẮT BUỘC trả lời mới đóng được (không có nút đóng, Esc hay bấm nền
 * đều không tắt); chỉ khi gửi lỗi mới có lối thoát để không kẹt người dùng. Mỗi lượt quét hỏi một lần (localStorage + chặn trùng ở máy chủ).
 */
export function FeedbackModal({ scanId }: { scanId: string }) {
  const key = `vibesec-fb-${scanId}`;
  const [show, setShow] = useState(false);
  const [rating, setRating] = useState(0);
  const [tags, setTags] = useState<string[]>([]);
  const [comment, setComment] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");

  useEffect(() => {
    let seen = false;
    try { seen = localStorage.getItem(key) === "1"; } catch { /* bỏ qua */ }
    if (seen) return;
    const t = setTimeout(() => setShow(true), 1800);
    return () => clearTimeout(t);
  }, [key]);

  const close = () => { setShow(false); try { localStorage.setItem(key, "1"); } catch { /* bỏ qua */ } };
  async function submit() {
    if (!rating) return;
    setState("sending");
    try {
      const r = await fetch("/api/feedback", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ scanId, rating, tags, comment }) });
      if (!r.ok) throw new Error();
      setState("done");
      try { localStorage.setItem(key, "1"); } catch { /* bỏ qua */ }
      setTimeout(() => setShow(false), 2200);
    } catch { setState("error"); }
  }

  if (!show) return null;
  return (
    <div className="fixed inset-0 z-[60] grid place-items-center overflow-y-auto bg-fg/40 p-3 backdrop-blur-[3px] print:hidden">
      <div role="dialog" aria-modal="true" aria-labelledby="fb-h" className="pop w-full max-w-md rounded-2xl border border-line bg-white p-5 shadow-card">
        {state === "done" ? (
          <div className="py-6 text-center"><Face className="mx-auto size-14" /><p className="mt-3 text-lg font-semibold">Cảm ơn bạn nhiều nha! 💙</p><p className="mt-1 text-sm text-muted">Mật Mật sẽ làm cho dễ hiểu hơn nữa.</p></div>
        ) : (
          <>
            <div className="flex items-start gap-3">
              <Face className="size-11 shrink-0" />
              <div className="min-w-0 flex-1"><h2 id="fb-h" className="text-[17px] font-semibold leading-snug"><Typed text="Quét xong rồi nè! Mật Mật hỏi nhỏ: báo cáo có dễ hiểu không?" cps={55} cursor={false} /></h2><p className="mt-1 text-sm text-muted">Bạn trả lời giúp mình một chút rồi tiếp tục dùng nhé 🐾</p></div>
            </div>
            <div role="radiogroup" aria-label="Đánh giá" className="mt-5 flex justify-between gap-1">
              {FACES.map(([e, label], i) => (
                <button key={label} role="radio" aria-checked={rating === i + 1} onClick={() => setRating(i + 1)} title={label}
                  className={`flex flex-1 flex-col items-center gap-1 rounded-xl border py-2 text-[11px] transition-all ${rating === i + 1 ? "scale-105 border-accent bg-accent-soft text-accent" : "border-line text-muted hover:border-line-strong"}`}>
                  <span className="text-2xl" aria-hidden>{e}</span>{label}
                </button>
              ))}
            </div>
            {rating > 0 && (
              <div className="fade-in mt-4">
                <p className="mb-2 text-sm font-medium">Điều gì đúng nhất? <span className="font-normal text-faint">(không bắt buộc)</span></p>
                <div className="flex flex-wrap gap-1.5">
                  {TAGS.map(([k, l]) => <button key={k} aria-pressed={tags.includes(k)} onClick={() => setTags((t) => t.includes(k) ? t.filter((x) => x !== k) : [...t, k])} className={`rounded-full border px-3 py-1 text-[12.5px] ${tags.includes(k) ? "border-accent bg-accent-soft text-accent" : "border-line-strong text-muted hover:border-fg/40"}`}>{l}</button>)}
                </div>
                <textarea value={comment} onChange={(e) => setComment(e.target.value)} maxLength={600} rows={3} placeholder="Chỗ nào khó hiểu? Bạn muốn thêm gì? (không bắt buộc)" aria-label="Góp ý thêm" className="input mt-3 !h-auto py-2.5" />
              </div>
            )}
            {state === "error" && <p role="alert" className="mt-3 text-sm text-crit">Chưa gửi được, bạn thử lại nhé.</p>}
            <div className="mt-5 flex justify-end gap-2">
              {state === "error" && <button onClick={close} className="btn-ghost btn-sm">Bỏ qua lần này</button>}
              <button onClick={() => void submit()} disabled={!rating || state === "sending"} className="btn-primary btn-sm">{state === "sending" ? "Đang gửi…" : "Gửi cho Mật Mật"}</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
