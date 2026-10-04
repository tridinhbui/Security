/** Score trend. Server-rendered SVG, no chart library. Points are [label, score]. */
export function Sparkline({ points }: { points: { label: string; score: number }[] }) {
  if (points.length < 2) return <p className="text-sm text-muted">Scan this site again to see a trend.</p>;
  const w = 320, h = 72, pad = 6;
  const xs = (i: number) => pad + (i * (w - pad * 2)) / (points.length - 1);
  const ys = (s: number) => h - pad - (s / 100) * (h - pad * 2);
  const d = points.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join(" ");
  const last = points[points.length - 1]!;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full max-w-xs h-[72px]" role="img" aria-label={`Score trend: ${points.map((p) => p.score).join(", ")}`}>
      <line x1={pad} x2={w - pad} y1={ys(80)} y2={ys(80)} stroke="var(--color-line)" strokeDasharray="3 4" />
      <path d={d} fill="none" stroke="var(--color-fg)" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={xs(points.length - 1)} cy={ys(last.score)} r="3" fill="var(--color-fg)" />
    </svg>
  );
}
