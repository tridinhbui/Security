import { encrypt } from "../crypto";
import type { D1Like } from "../db/d1";
import * as repo from "../db/repo";
import { log } from "../log";
import { ScanRefusedError, type ScanReport } from "../scanner/report";
import { recordSsrfStrike } from "./abuse";
import { ScannerUnavailableError, type ScannerClient } from "./scanner-client";

const BLOCKING_CODES = new Set(["non_public_ip", "dns_mixed_answers", "internal_hostname", "scheme_not_allowed", "port_not_allowed", "credentials_not_allowed"]);
export const MAX_ATTEMPTS = 3;

async function persist(db: D1Like, scanId: string, userId: string, report: ScanReport) {
  const user = await repo.getUserById(db, userId);
  await repo.completeScan(db, scanId, {
    score: report.score.score, grade: report.score.grade, categoryScores: report.score.categoryScores, severityCounts: report.score.severityCounts,
    platforms: report.platforms, requests: report.stats.requests, engineVersion: report.engineVersion, retentionDays: user?.retention_days ?? 90, findings: report.findings,
    targets: await Promise.all(report.targets.map(async (t) => ({
      role: t.role, url: t.url, finalUrl: t.finalUrl, status: t.status, tls: t.tls ?? null, headersEnc: await encrypt(JSON.stringify(t.headers)),
      resolved: t.resolved, errorCode: t.errorCode ?? null, durationMs: t.durationMs,
    }))),
  });
}

export type JobOutcome = "done" | "skipped" | "retry";

/**
 * Process one queue message. Claims the scan first (so duplicate/redelivered messages are harmless), runs the
 * scan via the scanner, and persists the result. Policy refusals fail the scan permanently; infrastructure faults
 * ask for a retry until MAX_ATTEMPTS, then fail the scan. Never logs scan content.
 */
export async function processScanJob(db: D1Like, scanId: string, scanner: ScannerClient): Promise<JobOutcome> {
  const scan = await repo.claimScan(db, scanId);
  if (!scan) return "skipped";
  const started = Date.now();
  const queueWaitMs = scan.started_at ? Math.max(0, Date.parse(scan.started_at) - Date.parse(scan.created_at)) : 0;
  const setStage = async (status: string) => {
    await repo.setScanStage(db, scan.id, status); // doubles as heartbeat
    await repo.recordEvent(db, { type: "stage", scanId: scan.id, userId: scan.user_id, level: "debug", message: status });
  };

  try {
    const report = await scanner.scan(scan.normalized_url, setStage, { quick: scan.mode === "quick" }); // query/fragment were stripped at creation
    await persist(db, scan.id, scan.user_id, report);
    const latency = Date.now() - started;
    await repo.recordEvent(db, { type: "scan_completed", scanId: scan.id, userId: scan.user_id, meta: { score: report.score.score, requests: report.stats.requests, latency_ms: latency, queue_wait_ms: queueWaitMs, hit_limit: report.stats.hitLimit, rule_errors: report.stats.ruleErrors.length } });
    return "done";
  } catch (e) {
    if (e instanceof ScanRefusedError) {
      if (BLOCKING_CODES.has(e.code)) await recordSsrfStrike(db, scan.user_id, { code: e.code, stage: "dns", host: scan.normalized_url.slice(0, 120) });
      await repo.failScan(db, scan.id, e.code, e.message);
      await repo.recordEvent(db, { type: "scan_refused", scanId: scan.id, userId: scan.user_id, level: "warn", message: e.code, meta: { code: e.code, latency_ms: Date.now() - started } });
      return "done";
    }
    const infra = e instanceof ScannerUnavailableError;
    log("error", "scan_job_error", { scan: scan.id, name: (e as Error).name, infra, attempt: scan.attempts });
    if (infra && scan.attempts < MAX_ATTEMPTS) {
      await repo.requeueScan(db, scan.id);
      return "retry";
    }
    await repo.failScan(db, scan.id, "internal_error", "Đã xảy ra lỗi trong quá trình quét. Vui lòng thử lại.");
    await repo.recordEvent(db, { type: "scan_failed", scanId: scan.id, userId: scan.user_id, level: "error", message: "internal_error", meta: { code: "internal_error", error_name: (e as Error).name, latency_ms: Date.now() - started, attempts: scan.attempts } });
    return "done";
  }
}
