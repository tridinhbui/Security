import type { Severity } from "./scanner/types";

export const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const SEV_COLOR: Record<Severity, string> = {
  critical: "text-crit", high: "text-high", medium: "text-med", low: "text-low", info: "text-info",
};
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

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(iso)) + " UTC";
}

export function relativeTime(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
