import type { Severity } from "./scanner/types";
export { SEV_LABEL } from "./i18n";
export const SEV_COLOR: Record<Severity, string> = {
  critical: "text-crit", high: "text-high", medium: "text-med", low: "text-low", info: "text-info",
};
/** Chip theo mức độ (định nghĩa trong globals.css). */
export const SEV_CHIP: Record<Severity, string> = { critical: "chip-crit", high: "chip-high", medium: "chip-med", low: "chip-low", info: "chip-info" };
/** Màu thanh/nền theo mức độ. */
export const SEV_BAR: Record<Severity, string> = { critical: "bg-crit", high: "bg-high", medium: "bg-med", low: "bg-low", info: "bg-info" };
export const SEV_RAIL: Record<Severity, string> = { critical: "border-l-crit", high: "border-l-high", medium: "border-l-med", low: "border-l-low", info: "border-l-line-strong" };

export const SEV_DOT: Record<Severity, string> = {
  critical: "bg-crit", high: "bg-high", medium: "bg-med", low: "bg-low", info: "bg-info",
};

export function gradeColor(grade: string | null | undefined): string {
  switch (grade) {
    case "A": return "text-ok";
    case "B": return "text-ok";
    case "C": return "text-med";
    case "D": return "text-high";
    case "F": return "text-crit";
    default: return "text-muted";
  }
}

export function scoreColor(score: number | null | undefined): string {
  if (score === null || score === undefined) return "text-muted";
  return score >= 80 ? "text-ok" : score >= 70 ? "text-med" : score >= 60 ? "text-high" : "text-crit";
}

const VN_TZ = "Asia/Ho_Chi_Minh";

/** Ngày giờ theo múi giờ Việt Nam (GMT+7), ví dụ "04 thg 10, 2026, 20:46". */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("vi-VN", { dateStyle: "medium", timeStyle: "short", timeZone: VN_TZ }).format(new Date(iso)) + " (GMT+7)";
}

export function relativeTime(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "vừa xong";
  if (s < 3600) return `${Math.floor(s / 60)} phút trước`;
  if (s < 86400) return `${Math.floor(s / 3600)} giờ trước`;
  return `${Math.floor(s / 86400)} ngày trước`;
}
