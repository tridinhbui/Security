"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface Msg { id: string; sender: "user" | "admin"; body: string; created_at: string }

/** Khung chat dùng chung cho người dùng (/api/chat) và quản trị viên (/api/admin/chat/:id). Thăm dò 4 giây một lần khi tab đang hiện. */
export function ChatBox({ endpoint, me, placeholder }: { endpoint: string; me: "user" | "admin"; placeholder: string }) {
  const [msgs, setMsgs] = useState<Msg[] | null>(null);
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const [sending, setSending] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const count = useRef(0);

  const load = useCallback(async () => {
    try {
      const r = await fetch(endpoint, { cache: "no-store" });
      if (r.ok) setMsgs(((await r.json()) as { messages: Msg[] }).messages);
    } catch { /* mạng chập chờn: lần thăm dò sau sẽ thử lại */ }
  }, [endpoint]);

  useEffect(() => {
    void load();
    const t = setInterval(() => { if (document.visibilityState === "visible") void load(); }, 4000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    if (msgs && msgs.length !== count.current) { count.current = msgs.length; endRef.current?.scrollIntoView({ block: "end" }); }
  }, [msgs]);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    const body = text.trim();
    if (!body || sending) return;
    setSending(true); setErr("");
    try {
      const r = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body }) });
      if (!r.ok) setErr(((await r.json().catch(() => null)) as { message?: string } | null)?.message ?? "Không gửi được tin nhắn.");
      else { setText(""); await load(); }
    } catch { setErr("Lỗi mạng. Vui lòng thử lại."); }
    setSending(false);
  }

  return (
    <div className="panel flex h-[28rem] flex-col overflow-hidden">
      <div className="flex-1 space-y-2 overflow-y-auto bg-surface p-4" aria-live="polite" aria-label="Tin nhắn">
        {msgs === null && <p className="text-sm text-faint">Đang tải…</p>}
        {msgs?.length === 0 && <p className="text-sm text-faint">Chưa có tin nhắn nào. Hãy gửi tin đầu tiên.</p>}
        {msgs?.map((m) => (
          <div key={m.id} className={`flex ${m.sender === me ? "justify-end" : "justify-start"}`}>
            <div className={`max-w-[80%] whitespace-pre-wrap break-words rounded-xl px-3 py-2 text-sm ${m.sender === me ? "bg-accent text-white" : "border border-line bg-white text-fg"}`}>
              {m.body}
              <div className={`mono mt-1 text-[10px] ${m.sender === me ? "text-white/70" : "text-faint"}`}>{new Date(m.created_at).toLocaleString("vi-VN")}</div>
            </div>
          </div>
        ))}
        <div ref={endRef} />
      </div>
      <form onSubmit={send} className="border-t border-line bg-white p-3">
        {err && <p role="alert" className="mb-2 text-xs text-crit">{err}</p>}
        <div className="flex gap-2">
          <input className="input" value={text} maxLength={1000} onChange={(e) => setText(e.target.value)} placeholder={placeholder} aria-label="Nội dung tin nhắn" />
          <button className="btn-primary" disabled={sending || !text.trim()}>Gửi</button>
        </div>
      </form>
    </div>
  );
}
