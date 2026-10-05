/** Xu hướng điểm. SVG render ở server, không dùng thư viện biểu đồ; đường "vẽ" dần khi xuất hiện. */
export function Sparkline({ points }: { points: { label: string; score: number }[] }) {
  if (points.length < 2) return <p className="text-sm text-muted">Hãy quét lại website này để xem xu hướng điểm.</p>;
  const w = 360, h = 88, pad = 8;
  const xs = (i: number) => pad + (i * (w - pad * 2)) / (points.length - 1);
  const ys = (s: number) => h - pad - (s / 100) * (h - pad * 2);
  const line = points.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join(" ");
  const area = `${line} L${xs(points.length - 1).toFixed(1)},${h - pad} L${xs(0).toFixed(1)},${h - pad} Z`;
  const last = points[points.length - 1]!;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-[88px] w-full max-w-sm" role="img" aria-label={`Xu hướng điểm: ${points.map((p) => p.score).join(", ")}`}>
      <defs><linearGradient id="spark-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.16" /><stop offset="100%" stopColor="var(--color-accent)" stopOpacity="0" /></linearGradient></defs>
      <line x1={pad} x2={w - pad} y1={ys(80)} y2={ys(80)} stroke="var(--color-line-strong)" strokeDasharray="3 4" />
      <text x={w - pad} y={ys(80) - 4} textAnchor="end" fontSize="9" fill="var(--color-faint)" fontFamily="var(--font-mono)">80</text>
      <path d={area} fill="url(#spark-fill)" />
      <path d={line} pathLength={1} className="draw-line" fill="none" stroke="var(--color-accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      {points.map((p, i) => <circle key={i} cx={xs(i)} cy={ys(p.score)} r={i === points.length - 1 ? 4 : 2.5} fill="white" stroke="var(--color-accent)" strokeWidth="2" />)}
    </svg>
  );
}
