"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { BotContext, Focus } from "@/lib/matmat";

export type Mode = "beginner" | "technical";
interface Ctx {
  mode: Mode; setMode: (m: Mode) => void;
  report: BotContext | null; setReport: (r: BotContext | null) => void;
  open: boolean; setOpen: (v: boolean) => void;
  /** Câu hỏi muốn Mật Mật trả lời ngay khi mở (ví dụ từ nút "Hỏi Mật Mật" trên một vấn đề). */
  ask: string | null; askMatMat: (q: string) => void; clearAsk: () => void;
  /** Mục/dòng đang được hỏi: chatbot tự dùng làm ngữ cảnh. */
  focus: Focus | null; setFocus: (f: Focus | null) => void;
  /** Mở chatbot và hỏi về đúng mục (hoặc dòng bằng chứng) này. */
  askAbout: (f: Focus, question?: string) => void;
}

const C = createContext<Ctx | null>(null);
export const useMatMat = () => {
  const v = useContext(C);
  if (!v) throw new Error("useMatMat phải nằm trong MatMatProvider");
  return v;
};

/** Giữ chế độ hiển thị (Dễ hiểu / Kỹ thuật) dùng chung cho cả trang và ngữ cảnh báo cáo hiện tại cho Mật Mật. */
export function MatMatProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<Mode>("beginner");
  const [report, setReport] = useState<BotContext | null>(null);
  const [open, setOpen] = useState(false);
  const [ask, setAsk] = useState<string | null>(null);
  const [focus, setFocus] = useState<Focus | null>(null);

  useEffect(() => {
    try { const m = localStorage.getItem("vibesec-mode"); if (m === "technical" || m === "beginner") setModeState(m); } catch { /* không đọc được localStorage */ }
  }, []);
  const setMode = useCallback((m: Mode) => { setModeState(m); try { localStorage.setItem("vibesec-mode", m); } catch { /* bỏ qua */ } }, []);
  const askMatMat = useCallback((q: string) => { setAsk(q); setOpen(true); }, []);
  const clearAsk = useCallback(() => setAsk(null), []);
  const askAbout = useCallback((f: Focus, question?: string) => { setFocus(f); setAsk(question ?? (f.line ? "Dòng này nghĩa là gì?" : "Giải thích mục này cho mình")); setOpen(true); }, []);
  useEffect(() => { setFocus(null); }, [report]); // đổi báo cáo thì bỏ mục đang chọn

  const value = useMemo(() => ({ mode, setMode, report, setReport, open, setOpen, ask, askMatMat, clearAsk, focus, setFocus, askAbout }), [mode, setMode, report, open, ask, askMatMat, clearAsk, focus, askAbout]);
  return <C.Provider value={value}>{children}</C.Provider>;
}
