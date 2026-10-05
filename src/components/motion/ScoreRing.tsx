"use client";
import { useEffect, useState } from "react";
import { scoreColor, gradeColor } from "@/lib/format";
import { AnimatedNumber } from "./AnimatedNumber";
import { useReducedMotion } from "./useReducedMotion";

/** Vòng điểm: stroke-dashoffset chuyển mượt tới giá trị thật; màu theo ngưỡng điểm. */
export function ScoreRing({ score, grade, size = 176 }: { score: number; grade: string; size?: number }) {
  const reduced = useReducedMotion();
  const [drawn, setDrawn] = useState(reduced ? score : 0);
  useEffect(() => {
    if (reduced) { setDrawn(score); return; }
    const id = requestAnimationFrame(() => setDrawn(score)); // đổi sau frame đầu để CSS transition chạy
    return () => cancelAnimationFrame(id);
  }, [score, reduced]);

  const stroke = 10, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const tone = score >= 80 ? "var(--color-ok)" : score >= 70 ? "var(--color-med)" : score >= 60 ? "var(--color-high)" : "var(--color-crit)";
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} role="img" aria-label={`Điểm ${score}, hạng ${grade}`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-line)" strokeWidth={stroke} />
        {/* vạch chia 80 điểm (ngưỡng "tốt") */}
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tone} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - drawn / 100)} style={{ transition: "stroke-dashoffset 1.1s var(--ease-out-expo), stroke 0.4s" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <AnimatedNumber value={score} className={`text-5xl font-semibold tracking-tighter ${scoreColor(score)}`} />
        <span className={`mt-0.5 font-mono text-sm font-medium ${gradeColor(grade)}`}>HẠNG {grade}</span>
      </div>
    </div>
  );
}
