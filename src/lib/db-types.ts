import type { ScanReport } from "./scanner/report";
import type { Finding, Severity } from "./scanner/types";

export type ScanStatus =
  | "queued" | "validating" | "scanning_transport" | "checking_headers"
  | "analyzing_client" | "generating_report" | "completed" | "failed";

export const PROGRESS_STEPS: { status: ScanStatus; label: string }[] = [
  { status: "queued", label: "Đang chờ trong hàng đợi" },
  { status: "validating", label: "Đang kiểm tra địa chỉ" },
  { status: "scanning_transport", label: "Đang quét đường truyền (HTTPS/TLS)" },
  { status: "checking_headers", label: "Đang kiểm tra HTTP header" },
  { status: "analyzing_client", label: "Đang phân tích mã công khai phía trình duyệt" },
  { status: "generating_report", label: "Đang tạo báo cáo" },
  { status: "completed", label: "Hoàn tất" },
];

export interface ScanRow {
  id: string;
  user_id: string;
  input_url: string;
  normalized_url: string;
  host: string;
  mode: "full" | "quick";
  status: ScanStatus;
  error_code: string | null;
  error_message: string | null;
  score: number | null;
  grade: "A" | "B" | "C" | "D" | "F" | null;
  category_scores: Record<string, number | null> | null;
  severity_counts: Record<Severity, number> | null;
  platforms: string[];
  request_count: number | null;
  attempts: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  expires_at: string | null;
}

export interface FindingRow {
  id: string;
  scan_id: string;
  rule_id: string;
  fingerprint: string;
  title: string;
  category: Finding["category"];
  severity: Severity;
  confidence: Finding["confidence"];
  status: Finding["status"];
  evidence: string[];
  explanation: string;
  summary: string;
  technical: string | null;
  remediation: Finding["remediation"];
  affected_url: string | null;
  references: Finding["references"];
}

export interface TargetView {
  role: string;
  url: string;
  final_url: string | null;
  status_code: number | null;
  tls: ScanReport["targets"][number]["tls"] | null;
  headers: Record<string, string | string[]> | null;
  error_code: string | null;
}

export interface ReportView {
  scan: ScanRow;
  findings: FindingRow[];
  targets: TargetView[];
}

export function rowToFinding(r: FindingRow): Finding {
  return {
    ruleId: r.rule_id, title: r.title, category: r.category, severity: r.severity, confidence: r.confidence, status: r.status,
    summary: r.summary, explanation: r.explanation, technical: r.technical ?? undefined, evidence: r.evidence ?? [],
    remediation: r.remediation, affectedUrl: r.affected_url, references: r.references ?? [], fingerprint: r.fingerprint,
  };
}
