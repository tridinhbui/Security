import { gradeFor, penalty, PASSIVE_SCORE_CEILING, type Grade } from "../scanner/score";
import { SEVERITIES, type Confidence, type Severity } from "../scanner/types";

/** pass = đã kiểm tra, ổn · fail = có vấn đề · info = chỉ để biết · unknown = chưa kiểm tra được */
export type ItemStatus = "pass" | "fail" | "info" | "unknown";
export type ItemSource = "website" | "code" | "system";

export interface ProjectItem {
  /** Mã luật ổn định (dùng để so sánh Before/After). */
  id: string;
  /** Ổn định giữa các lượt quét cùng mục tiêu. */
  fingerprint: string;
  group: string;
  source?: ItemSource;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: ItemStatus;
  /** "Chuyện gì đang xảy ra" — đời thường. */
  summary: string;
  /** "Vì sao nên quan tâm". */
  why: string;
  fix?: { summary: string; steps?: string[]; snippet?: { label: string; language: string; code: string } };
  /** Dòng bằng chứng ĐÃ che bí mật (đường dẫn:dòng, độ dài…). Không bao giờ chứa giá trị đầy đủ. */
  evidence: string[];
  technical?: string;
  /** Nút hành động (ví dụ "Quét mã nguồn" khi một nguồn chưa được quét). */
  action?: { label: string; href: string };
}

export interface ItemScore { score: number; grade: Grade; counts: Record<Severity, number>; passed: number; failed: number }

/** Cùng công thức với quét website: điểm = 100 − Σ phạt; có Critical → tối đa 59; có High → tối đa 79. */
export function scoreItems(items: ProjectItem[]): ItemScore {
  const fails = items.filter((i) => i.status === "fail");
  let score = Math.max(0, 100 - items.reduce((a, i) => a + penalty(i), 0));
  if (fails.some((i) => i.severity === "critical")) score = Math.min(score, 59);
  else if (fails.some((i) => i.severity === "high")) score = Math.min(score, 79);
  score = Math.round(Math.min(score, PASSIVE_SCORE_CEILING));
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const i of fails) counts[i.severity]++;
  return { score, grade: gradeFor(score), counts, passed: items.filter((i) => i.status === "pass").length, failed: fails.length };
}

export const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const bySeverity = (a: ProjectItem, b: ProjectItem) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity];

/** Dùng chung: tạo mục với giá trị mặc định hợp lý. */
export function item(p: Omit<ProjectItem, "fingerprint" | "evidence" | "confidence"> & { fingerprint?: string; evidence?: string[]; confidence?: Confidence }): ProjectItem {
  return { confidence: "high", evidence: [], fingerprint: p.id, ...p };
}

export type LaunchVerdict = "ready" | "fix_first" | "not_ready";
export const VERDICT_LABEL: Record<LaunchVerdict, string> = { ready: "Sẵn sàng", fix_first: "Nên sửa trước khi ra mắt", not_ready: "Chưa nên ra mắt" };
