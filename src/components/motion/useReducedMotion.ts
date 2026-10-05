"use client";
import { useEffect, useState } from "react";

/** true khi người dùng yêu cầu giảm chuyển động. Mặc định false ở server để HTML khớp, cập nhật ngay sau khi mount. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(mq.matches);
    const on = () => setReduced(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return reduced;
}
