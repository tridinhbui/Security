"use client";

import { useEffect, useRef, useState } from "react";
import { GREETING, chipsFor, reply, type BotReply } from "@/lib/matmat";
import { ChatBox } from "../ChatBox";
import { Typed } from "../motion/Typed";
import { useMatMat } from "./MatMatProvider";

interface Msg { from: "bot" | "me"; text: string; chips?: string[]; copy?: BotReply["copy"]; typing?: boolean }

export function Face({ className = "size-9" }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" className={className} aria-hidden>
      <circle cx="20" cy="20" r="20" fill="var(--color-accent)" />
      <path d="M8 13 12 5l6 6M32 13l-4-8-6 6" fill="var(--color-accent-strong)" />
      <circle cx="20" cy="22" r="12" fill="#fff" />
      <circle cx="15.5" cy="21" r="1.8" fill="#0b1220" /><circle cx="24.5" cy="21" r="1.8" fill="#0b1220" />
      <path d="M17 26c1.6 1.6 4.4 1.6 6 0" stroke="#0b1220" strokeWidth="1.6" strokeLinecap="round" fill="none" />
      <circle cx="12.5" cy="25" r="1.8" fill="#ffb4c0" opacity=".8" /><circle cx="27.5" cy="25" r="1.8" fill="#ffb4c0" opacity=".8" />
    </svg>
  );
}

/** Mật Mật: trợ lý nổi, trả lời bằng nội dung viết sẵn (không dùng AI) với hiệu ứng gõ chữ. */
export function MatMat({ authed }: { authed: boolean }) {
  const { open, setOpen, report, ask, clearAsk } = useMatMat();
  const [msgs, setMsgs] = useState<Msg[]>([{ from: "bot", text: GREETING, chips: chipsFor(null) }]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [human, setHuman] = useState(false);
  const [copied, setCopied] = useState<number | null>(null);
  const [nudge, setNudge] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);
  useEffect(() => { endRef.current?.scrollIntoView({ block: "end" }); }, [msgs, human, open]);
  // Đổi sang báo cáo khác thì gợi ý đổi theo
  useEffect(() => {
    setMsgs((m) => m.length === 1 ? [{ from: "bot", text: report ? `Chào bạn, mình là Mật Mật 🐾 Mình vừa xem báo cáo của ${report.host}. Có chỗ nào khó hiểu thì hỏi mình nha!` : GREETING, chips: chipsFor(report) }] : m);
  }, [report]);
  useEffect(() => {
    let seen = false;
    try { seen = sessionStorage.getItem("matmat-nudge") === "1"; } catch { /* bỏ qua */ }
    if (seen) return;
    const t = setTimeout(() => { setNudge(true); try { sessionStorage.setItem("matmat-nudge", "1"); } catch { /* bỏ qua */ } }, 4000);
    return () => clearTimeout(t);
  }, []);

  function send(raw: string) {
    const q = raw.trim();
    if (!q || busy) return;
    setText("");
    setMsgs((m) => [...m.map((x) => ({ ...x, chips: undefined })), { from: "me", text: q }]);
    setBusy(true);
    const r = reply(q, report);
    // "đang nghĩ…" ngắn rồi mới gõ chữ, cho cảm giác như đang trò chuyện
    timers.current.push(setTimeout(() => {
      setMsgs((m) => [...m, { from: "bot", text: r.text, chips: r.chips, copy: r.copy, typing: true }]);
      if (r.handoff) setHuman(true);
    }, 450));
  }
  const done = () => { setBusy(false); setMsgs((m) => m.map((x) => ({ ...x, typing: false }))); };

  useEffect(() => {
    if (ask && open) { send(ask); clearAsk(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ask, open]);

  async function copy(i: number, t: string) {
    try { await navigator.clipboard.writeText(t); setCopied(i); setTimeout(() => setCopied(null), 2000); } catch { /* trình duyệt chặn clipboard */ }
  }

  return (
    <>
      {!open && (
        <div className="fixed bottom-5 right-5 z-40 flex items-end gap-3 print:hidden">
          {nudge && <button onClick={() => { setOpen(true); setNudge(false); }} className="pop mb-1 max-w-52 rounded-2xl rounded-br-sm border border-line bg-white px-3.5 py-2.5 text-left text-[13px] shadow-pop">Khó hiểu chỗ nào? Hỏi Mật Mật nha 🐾</button>}
          <button onClick={() => setOpen(true)} aria-label="Mở trò chuyện với Mật Mật" className="float-y rounded-full shadow-glow transition-transform hover:scale-105"><Face className="size-14" /></button>
        </div>
      )}
      {open && (
        <section role="dialog" aria-label="Mật Mật — trợ lý" className="pop fixed inset-x-3 bottom-3 z-50 flex max-h-[80dvh] flex-col overflow-hidden rounded-2xl border border-line bg-white shadow-card sm:inset-x-auto sm:right-5 sm:bottom-5 sm:w-[24rem] print:hidden">
          <header className="flex items-center gap-3 border-b border-line bg-surface px-4 py-3">
            <Face />
            <div className="min-w-0 flex-1"><p className="text-sm font-semibold leading-tight">Mật Mật</p><p className="text-xs text-muted">Giải thích dễ hiểu · không dùng AI</p></div>
            <button onClick={() => setOpen(false)} aria-label="Đóng" className="grid size-8 place-items-center rounded-lg text-muted hover:bg-raised hover:text-fg"><svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 6l12 12M18 6 6 18" /></svg></button>
          </header>

          {human ? (
            <div className="min-h-0 flex-1 overflow-y-auto p-3">
              <button onClick={() => setHuman(false)} className="mb-2 text-xs text-accent hover:underline">← Quay lại Mật Mật</button>
              {authed ? <ChatBox endpoint="/api/chat" me="user" placeholder="Nhắn cho đội hỗ trợ…" /> : <p className="rounded-xl bg-surface p-4 text-sm text-muted">Bạn cần <a className="font-medium text-accent hover:underline" href="/login">đăng nhập</a> để nhắn đội hỗ trợ nhé.</p>}
            </div>
          ) : (
            <>
              <div className="min-h-[14rem] flex-1 space-y-3 overflow-y-auto p-4" aria-live="polite">
                {msgs.map((m, i) => (
                  <div key={i} className={m.from === "me" ? "flex justify-end" : "flex gap-2"}>
                    {m.from === "bot" && <Face className="mt-0.5 size-7 shrink-0" />}
                    <div className="min-w-0 max-w-[85%]">
                      <div className={`whitespace-pre-wrap break-words rounded-2xl px-3.5 py-2.5 text-[14px] leading-relaxed ${m.from === "me" ? "rounded-br-sm bg-accent text-white" : "rounded-bl-sm bg-surface text-fg"}`}>
                        {m.from === "bot" && m.typing && i === msgs.length - 1 ? <Typed text={m.text} cps={70} onDone={done} /> : m.text}
                      </div>
                      {m.copy && !m.typing && (
                        <button onClick={() => void copy(i, m.copy!.text)} className="btn-primary btn-sm mt-2 w-full">{copied === i ? "Đã copy ✓" : m.copy.label}</button>
                      )}
                      {m.chips && !m.typing && !busy && (
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {m.chips.map((c) => <button key={c} onClick={() => send(c)} className="rounded-full border border-line-strong bg-white px-3 py-1 text-[12.5px] text-muted transition-colors hover:border-accent hover:text-accent">{c}</button>)}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {busy && !msgs[msgs.length - 1]?.typing && msgs[msgs.length - 1]?.from === "me" && (
                  <div className="flex gap-2"><Face className="mt-0.5 size-7 shrink-0" /><div className="flex gap-1 rounded-2xl rounded-bl-sm bg-surface px-3.5 py-3" aria-label="Mật Mật đang trả lời">{[0, 1, 2].map((d) => <span key={d} className="size-1.5 animate-bounce rounded-full bg-faint" style={{ animationDelay: `${d * 120}ms` }} />)}</div></div>
                )}
                <div ref={endRef} />
              </div>
              <form onSubmit={(e) => { e.preventDefault(); send(text); }} className="flex gap-2 border-t border-line p-3">
                <input className="input !h-10" value={text} maxLength={200} onChange={(e) => setText(e.target.value)} placeholder="Hỏi Mật Mật bất cứ điều gì…" aria-label="Câu hỏi cho Mật Mật" />
                <button className="btn-primary !h-10" disabled={busy || !text.trim()}>Gửi</button>
              </form>
            </>
          )}
        </section>
      )}
    </>
  );
}
