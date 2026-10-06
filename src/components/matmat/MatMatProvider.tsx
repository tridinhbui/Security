"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { BotContext } from "@/lib/matmat";

export type Mode = "beginner" | "technical";
interface Ctx {
  mode: Mode; setMode: (m: Mode) => void;
  report: BotContext | null; setReport: (r: BotContext | null) => void;
  open: boolean; setOpen: (v: boolean) => void;
  /** Câu hỏi muốn Mật Mật trả lời ngay khi mở (ví dụ từ nút "Hỏi Mật Mật" trên một vấn đề). */
  ask: string | null; askMatMat: (q: string) => void; clearAsk: () => void;
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

  useEffect(() => {
    try { const m = localStorage.getItem("vibesec-mode"); if (m === "technical" || m === "beginner") setModeState(m); } catch { /* không đọc được localStorage */ }
  }, []);
  const setMode = useCallback((m: Mode) => { setModeState(m); try { localStorage.setItem("vibesec-mode", m); } catch { /* bỏ qua */ } }, []);
  const askMatMat = useCallback((q: string) => { setAsk(q); setOpen(true); }, []);
  const clearAsk = useCallback(() => setAsk(null), []);

  const value = useMemo(() => ({ mode, setMode, report, setReport, open, setOpen, ask, askMatMat, clearAsk }), [mode, setMode, report, open, ask, askMatMat, clearAsk]);
  return <C.Provider value={value}>{children}</C.Provider>;
}
