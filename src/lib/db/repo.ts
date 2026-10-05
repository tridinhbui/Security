import type { FindingRow, ScanRow, TargetView } from "../db-types";
import { log } from "../log";
import type { Finding } from "../scanner/types";
import { isoAgo, isoIn, newId, nowIso, parseJson, type D1Like } from "./d1";

/**
 * Data access. D1 has no row-level security, so the ownership rule is enforced HERE: every function
 * that returns or mutates user data takes the acting userId and puts it in the WHERE clause.
 * Functions without a userId are for the queue consumer / cron / public-share paths only.
 */

// ------------------------------------------------------------------ users

export interface UserRow { id: string; email: string; password_hash: string; retention_days: number; abuse_score: number; blocked_until: string | null; created_at: string; google_sub: string | null; display_name: string | null; avatar_url: string | null }

export async function createUser(db: D1Like, email: string, passwordHash: string): Promise<{ ok: true; id: string } | { ok: false; reason: "exists" }> {
  const id = newId();
  try {
    await db.prepare("INSERT INTO users (id,email,password_hash,created_at) VALUES (?,?,?,?)").bind(id, email, passwordHash, nowIso()).run();
    return { ok: true, id };
  } catch (e) {
    if (/UNIQUE/i.test(String((e as Error).message))) return { ok: false, reason: "exists" };
    throw e;
  }
}
export const OAUTH_PASSWORD_MARKER = "oauth:google";

/**
 * Tạo hoặc liên kết tài khoản từ danh tính Google ĐÃ XÁC MINH (email_verified=true được kiểm tra ở lớp trên).
 * Thứ tự: trùng google_sub → cập nhật hồ sơ; trùng email → liên kết (an toàn vì Google đã xác minh quyền sở hữu email);
 * không có → tạo mới. Không bao giờ tạo bản sao.
 */
export async function upsertGoogleUser(db: D1Like, g: { sub: string; email: string; name?: string | null; picture?: string | null }): Promise<{ user: UserRow; created: boolean }> {
  const bySub = await db.prepare("SELECT * FROM users WHERE google_sub = ?").bind(g.sub).first<UserRow>();
  if (bySub) {
    await db.prepare("UPDATE users SET display_name = ?, avatar_url = ? WHERE id = ?").bind(g.name ?? null, g.picture ?? null, bySub.id).run();
    return { user: { ...bySub, display_name: g.name ?? null, avatar_url: g.picture ?? null }, created: false };
  }
  const byEmail = await getUserByEmail(db, g.email);
  if (byEmail) {
    if (byEmail.google_sub && byEmail.google_sub !== g.sub) throw new Error("email_linked_to_other_google_account");
    await db.prepare("UPDATE users SET google_sub = ?, display_name = COALESCE(display_name, ?), avatar_url = ? WHERE id = ?").bind(g.sub, g.name ?? null, g.picture ?? null, byEmail.id).run();
    return { user: { ...byEmail, google_sub: g.sub, display_name: byEmail.display_name ?? g.name ?? null, avatar_url: g.picture ?? null }, created: false };
  }
  const id = newId();
  try {
    await db.prepare("INSERT INTO users (id,email,password_hash,created_at,google_sub,display_name,avatar_url) VALUES (?,?,?,?,?,?,?)")
      .bind(id, g.email, OAUTH_PASSWORD_MARKER, nowIso(), g.sub, g.name ?? null, g.picture ?? null).run();
  } catch (e) {
    if (/UNIQUE/i.test(String((e as Error).message))) { // hai callback đồng thời: lấy bản vừa được tạo
      const again = await db.prepare("SELECT * FROM users WHERE google_sub = ? OR email = ?").bind(g.sub, g.email).first<UserRow>();
      if (again) return { user: again, created: false };
    }
    throw e;
  }
  return { user: (await getUserById(db, id))!, created: true };
}

export const getUserByEmail = (db: D1Like, email: string) => db.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRow>();
export const getUserById = (db: D1Like, id: string) => db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRow>();

/** Changes retention and immediately re-dates the user's existing completed reports. */
export async function setRetention(db: D1Like, userId: string, days: 7 | 30 | 90 | 365) {
  await db.batch([
    db.prepare("UPDATE users SET retention_days = ? WHERE id = ?").bind(days, userId),
    db.prepare("UPDATE scans SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', completed_at, '+' || ? || ' days') WHERE user_id = ? AND completed_at IS NOT NULL").bind(days, userId),
  ]);
}
export const blockUser = (db: D1Like, userId: string, until: string) => db.prepare("UPDATE users SET blocked_until = ?, abuse_score = abuse_score + 1 WHERE id = ?").bind(until, userId).run();

// ------------------------------------------------------------------ sessions

export async function insertSession(db: D1Like, idHash: string, userId: string, expiresAt: string) {
  await db.prepare("INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES (?,?,?,?)").bind(idHash, userId, nowIso(), expiresAt).run();
}
export const getSessionUser = (db: D1Like, idHash: string) =>
  db.prepare("SELECT u.*, s.expires_at AS session_expires FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?")
    .bind(idHash, nowIso()).first<UserRow & { session_expires: string }>();
export const extendSession = (db: D1Like, idHash: string, expiresAt: string) => db.prepare("UPDATE sessions SET expires_at = ? WHERE id = ?").bind(expiresAt, idHash).run();
export const deleteSession = (db: D1Like, idHash: string) => db.prepare("DELETE FROM sessions WHERE id = ?").bind(idHash).run();
export const deleteUserSessions = (db: D1Like, userId: string) => db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();

// ------------------------------------------------------------------ auth throttling

export type AttemptKind = "login_fail_email" | "login_fail_ip" | "signup_ip" | "oauth_fail_ip";
export const recordAttempt = (db: D1Like, kind: AttemptKind, key: string) => db.prepare("INSERT INTO auth_attempts (kind,key,at) VALUES (?,?,?)").bind(kind, key, nowIso()).run();
export async function countAttempts(db: D1Like, kind: AttemptKind, key: string, windowMs: number): Promise<number> {
  const r = await db.prepare("SELECT COUNT(*) AS c FROM auth_attempts WHERE kind = ? AND key = ? AND at > ?").bind(kind, key, isoAgo(windowMs)).first<{ c: number }>();
  return r?.c ?? 0;
}
export const clearAttempts = (db: D1Like, kind: AttemptKind, key: string) => db.prepare("DELETE FROM auth_attempts WHERE kind = ? AND key = ?").bind(kind, key).run();

// ------------------------------------------------------------------ scans

export function rowToScan(r: Record<string, unknown>): ScanRow {
  return {
    ...(r as unknown as ScanRow),
    category_scores: parseJson(r.category_scores, null),
    severity_counts: parseJson(r.severity_counts, null),
    platforms: parseJson<string[]>(r.platforms, []),
  };
}

export type ScanMode = "full" | "quick";
export interface ScanLimits { maxConcurrent: number; hourly: number; daily: number; monthly: number; globalDaily: number; ipHourly: number; hostHourly: number }
export type CreateScanOutcome = { ok: true; id: string } | { ok: false; code: "account_blocked" | "too_many_concurrent" | "hourly_limit" | "daily_quota" | "monthly_quota" | "global_cap" | "ip_limit" | "host_limit"; retryAfter?: string };

const HOUR = 3_600_000, DAY = 86_400_000, MONTH = 30 * DAY;

/**
 * Enqueue a scan, enforcing every limit in ONE atomic INSERT…SELECT…WHERE statement. SQLite/D1 serialises
 * writes, so concurrent requests cannot slip past a limit (the TOCTOU a read-then-insert would have).
 * When the insert is refused we run read-only diagnostics to tell the caller which limit was hit.
 */
export async function createScanChecked(db: D1Like, a: { userId: string; url: string; host: string; ipHash: string | null; limits: ScanLimits; mode?: ScanMode }): Promise<CreateScanOutcome> {
  const id = newId();
  const now = nowIso();
  const hourAgo = isoAgo(HOUR), dayAgo = isoAgo(DAY), monthAgo = isoAgo(MONTH);
  const L = a.limits;
  const res = await db.prepare(`
    INSERT INTO scans (id,user_id,input_url,normalized_url,host,ip_hash,status,created_at,mode)
    SELECT ?,?,?,?,?,?, 'queued', ?, ?
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE id = ? AND blocked_until IS NOT NULL AND blocked_until > ?)
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND user_id = ? AND status NOT IN ('completed','failed')) < ?
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND user_id = ? AND created_at > ?) < ?
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND user_id = ? AND created_at > ?) < ?
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND user_id = ? AND created_at > ?) < ?
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND created_at > ?) < ?
      AND (? IS NULL OR (SELECT COUNT(*) FROM scans WHERE cached = 0 AND ip_hash = ? AND created_at > ?) < ?)
      AND (SELECT COUNT(*) FROM scans WHERE cached = 0 AND host = ? AND created_at > ?) < ?`)
    .bind(id, a.userId, a.url, a.url, a.host, a.ipHash, now, a.mode ?? "full",
      a.userId, now,
      a.userId, L.maxConcurrent,
      a.userId, hourAgo, L.hourly,
      a.userId, dayAgo, L.daily,
      a.userId, monthAgo, L.monthly,
      dayAgo, L.globalDaily,
      a.ipHash, a.ipHash, hourAgo, L.ipHourly,
      a.host, hourAgo, L.hostHourly).run();
  if ((res.meta.changes ?? 0) === 1) return { ok: true, id };

  const count = async (sql: string, ...p: (string | number | null)[]) => (await db.prepare(sql).bind(...p).first<{ c: number }>())?.c ?? 0;
  const u = await getUserById(db, a.userId);
  if (u?.blocked_until && u.blocked_until > now) return { ok: false, code: "account_blocked", retryAfter: u.blocked_until };
  if ((await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND user_id=? AND status NOT IN ('completed','failed')", a.userId)) >= L.maxConcurrent) return { ok: false, code: "too_many_concurrent" };
  if ((await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND user_id=? AND created_at>?", a.userId, hourAgo)) >= L.hourly) return { ok: false, code: "hourly_limit" };
  if ((await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND user_id=? AND created_at>?", a.userId, dayAgo)) >= L.daily) return { ok: false, code: "daily_quota" };
  if ((await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND user_id=? AND created_at>?", a.userId, monthAgo)) >= L.monthly) return { ok: false, code: "monthly_quota" };
  if ((await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND created_at>?", dayAgo)) >= L.globalDaily) return { ok: false, code: "global_cap" };
  if (a.ipHash && (await count("SELECT COUNT(*) c FROM scans WHERE cached = 0 AND ip_hash=? AND created_at>?", a.ipHash, hourAgo)) >= L.ipHourly) return { ok: false, code: "ip_limit" };
  return { ok: false, code: "host_limit" };
}

export async function getScan(db: D1Like, userId: string, id: string): Promise<ScanRow | null> {
  const r = await db.prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?").bind(id, userId).first();
  return r ? rowToScan(r) : null;
}
/** Internal (queue consumer / public share): NOT scoped to a user. Never expose directly. */
export async function getScanInternal(db: D1Like, id: string): Promise<ScanRow | null> {
  const r = await db.prepare("SELECT * FROM scans WHERE id = ?").bind(id).first();
  return r ? rowToScan(r) : null;
}
export async function listScans(db: D1Like, userId: string, limit: number): Promise<ScanRow[]> {
  const { results } = await db.prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?").bind(userId, limit).all();
  return results.map(rowToScan);
}
export async function countScansSince(db: D1Like, userId: string, since: string): Promise<number> {
  return (await db.prepare("SELECT COUNT(*) c FROM scans WHERE user_id = ? AND created_at > ?").bind(userId, since).first<{ c: number }>())?.c ?? 0;
}
export async function earlierCompleted(db: D1Like, userId: string, url: string, before: string, limit: number, onlyId?: string): Promise<ScanRow[]> {
  const { results } = await db.prepare(`SELECT * FROM scans WHERE user_id = ? AND normalized_url = ? AND status = 'completed' AND created_at < ? ${onlyId ? "AND id = ?" : ""} ORDER BY created_at DESC LIMIT ?`)
    .bind(...([userId, url, before, ...(onlyId ? [onlyId] : []), limit] as (string | number)[])).all();
  return results.map(rowToScan);
}
export async function deleteScan(db: D1Like, userId: string, id: string): Promise<boolean> {
  const r = await db.prepare("DELETE FROM scans WHERE id = ? AND user_id = ?").bind(id, userId).run(); // cascades findings/targets/shares/events
  return (r.meta.changes ?? 0) > 0;
}
export async function deleteAllScans(db: D1Like, userId: string): Promise<number> {
  return (await db.prepare("DELETE FROM scans WHERE user_id = ?").bind(userId).run()).meta.changes ?? 0;
}

// ---- queue / worker side

/**
 * Claim a queued scan (or take over one whose worker died: locked_at is stale). Returns null if it is
 * already running/finished, which makes queue redelivery and duplicate messages harmless.
 */
export async function claimScan(db: D1Like, id: string, staleMs = 3 * 60_000): Promise<ScanRow | null> {
  const now = nowIso();
  const r = await db.prepare(`
    UPDATE scans SET status = 'validating', locked_at = ?, started_at = COALESCE(started_at, ?), attempts = attempts + 1
    WHERE id = ? AND (status = 'queued' OR (status NOT IN ('completed','failed') AND locked_at < ?))
    RETURNING *`).bind(now, now, id, isoAgo(staleMs)).first();
  return r ? rowToScan(r) : null;
}
/** Progress update that doubles as the heartbeat. Refuses to move a terminal scan. */
export const setScanStage = (db: D1Like, id: string, status: string) =>
  db.prepare("UPDATE scans SET status = ?, locked_at = ? WHERE id = ? AND status NOT IN ('completed','failed')").bind(status, nowIso(), id).run();

export async function failScan(db: D1Like, id: string, code: string, message: string) {
  await db.prepare("UPDATE scans SET status='failed', error_code=?, error_message=?, completed_at=?, locked_at=NULL WHERE id=? AND status NOT IN ('completed','failed')").bind(code, message, nowIso(), id).run();
}

export interface CompleteInput {
  score: number; grade: string; categoryScores: unknown; severityCounts: unknown; platforms: string[]; requests: number; retentionDays: number;
  findings: Finding[]; targets: { role: string; url: string; finalUrl: string; status: number | null; tls: unknown; headersEnc: string; resolved: string[]; errorCode: string | null; durationMs: number }[];
}

/** Persist findings, targets and the final scan row in one transaction (all-or-nothing). */
export async function completeScan(db: D1Like, scanId: string, c: CompleteInput) {
  const done = new Date();
  const stmts = [
    ...c.findings.map((f) => db.prepare(`INSERT INTO findings (id,scan_id,rule_id,fingerprint,title,category,severity,confidence,status,evidence,explanation,summary,technical,remediation,affected_url,refs)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(newId(), scanId, f.ruleId, f.fingerprint, f.title, f.category, f.severity, f.confidence, f.status,
      JSON.stringify(f.evidence), f.explanation, f.summary, f.technical ?? null, JSON.stringify(f.remediation ?? {}), f.affectedUrl, JSON.stringify(f.references))),
    ...c.targets.map((t) => db.prepare(`INSERT INTO scan_targets (id,scan_id,role,url,final_url,status_code,tls,headers_enc,resolved_ips,error_code,duration_ms,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(newId(), scanId, t.role, t.url, t.finalUrl, t.status, t.tls ? JSON.stringify(t.tls) : null, t.headersEnc, JSON.stringify(t.resolved), t.errorCode, t.durationMs, done.toISOString())),
    db.prepare(`UPDATE scans SET status='completed', score=?, grade=?, category_scores=?, severity_counts=?, platforms=?, request_count=?, completed_at=?, expires_at=?, locked_at=NULL WHERE id=?`)
      .bind(c.score, c.grade, JSON.stringify(c.categoryScores), JSON.stringify(c.severityCounts), JSON.stringify(c.platforms), c.requests, done.toISOString(), new Date(done.getTime() + c.retentionDays * 86_400_000).toISOString(), scanId),
  ];
  await db.batch(stmts);
}

/** Cron: scans that never reached the consumer (lost message) should be re-sent; hung ones failed. */
export async function staleQueued(db: D1Like, olderThanMs: number): Promise<string[]> {
  const { results } = await db.prepare("SELECT id FROM scans WHERE status = 'queued' AND created_at < ? LIMIT 50").bind(isoAgo(olderThanMs)).all<{ id: string }>();
  return results.map((r) => r.id);
}
export async function reapHung(db: D1Like, olderThanMs: number): Promise<number> {
  const r = await db.prepare("UPDATE scans SET status='failed', error_code='timeout', error_message='Scan did not finish in time.', completed_at=?, locked_at=NULL WHERE status NOT IN ('queued','completed','failed') AND locked_at < ?").bind(nowIso(), isoAgo(olderThanMs)).run();
  return r.meta.changes ?? 0;
}
export async function purgeExpired(db: D1Like): Promise<{ scans: number; sessions: number; events: number; attempts: number }> {
  const now = nowIso();
  const [s, se, ev, at] = await db.batch([
    db.prepare("DELETE FROM scans WHERE expires_at IS NOT NULL AND expires_at < ?").bind(now),
    db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    db.prepare("DELETE FROM scan_events WHERE created_at < ?").bind(isoAgo(180 * DAY)),
    db.prepare("DELETE FROM auth_attempts WHERE at < ?").bind(isoAgo(DAY)),
    db.prepare("DELETE FROM tls_cache WHERE fetched_at < ?").bind(isoAgo(2 * DAY)),
  ]);
  return { scans: s!.meta.changes ?? 0, sessions: se!.meta.changes ?? 0, events: ev!.meta.changes ?? 0, attempts: at!.meta.changes ?? 0 };
}

// ------------------------------------------------------------------ findings / targets (call only after ownership is established)

function rowToFinding(r: Record<string, unknown>): FindingRow {
  return {
    ...(r as unknown as FindingRow),
    evidence: parseJson<string[]>(r.evidence, []),
    remediation: parseJson(r.remediation, null),
    references: parseJson(r.refs, []),
  };
}
export async function listFindings(db: D1Like, scanId: string): Promise<FindingRow[]> {
  const { results } = await db.prepare("SELECT * FROM findings WHERE scan_id = ?").bind(scanId).all();
  return results.map(rowToFinding);
}
export async function listTargetsRaw(db: D1Like, scanId: string) {
  const { results } = await db.prepare("SELECT role,url,final_url,status_code,tls,headers_enc,error_code FROM scan_targets WHERE scan_id = ? ORDER BY created_at").bind(scanId).all();
  return results as unknown as Array<Omit<TargetView, "tls" | "headers"> & { tls: string | null; headers_enc: string | null }>;
}
/** High/critical failing findings for the user's given scans (ownership enforced by joining scans). */
export async function openCriticalFindings(db: D1Like, userId: string, scanIds: string[]) {
  if (scanIds.length === 0) return [];
  const q = scanIds.map(() => "?").join(",");
  const { results } = await db.prepare(`SELECT f.scan_id, f.title, f.severity, f.rule_id FROM findings f JOIN scans s ON s.id = f.scan_id
    WHERE s.user_id = ? AND f.scan_id IN (${q}) AND f.status = 'fail' AND f.severity IN ('critical','high') LIMIT 50`).bind(userId, ...scanIds).all<{ scan_id: string; title: string; severity: "critical" | "high"; rule_id: string }>();
  return results;
}

// ------------------------------------------------------------------ shares

export async function createShare(db: D1Like, a: { scanId: string; userId: string; tokenHash: string; expiresAt: string | null }) {
  await db.prepare("INSERT INTO report_shares (id,scan_id,created_by,token_hash,created_at,expires_at) VALUES (?,?,?,?,?,?)").bind(newId(), a.scanId, a.userId, a.tokenHash, nowIso(), a.expiresAt).run();
}
export const getShareByHash = (db: D1Like, hash: string) =>
  db.prepare("SELECT scan_id, revoked_at, expires_at FROM report_shares WHERE token_hash = ?").bind(hash).first<{ scan_id: string; revoked_at: string | null; expires_at: string | null }>();
export async function revokeShares(db: D1Like, userId: string, scanId: string): Promise<number> {
  return (await db.prepare("DELETE FROM report_shares WHERE scan_id = ? AND created_by = ?").bind(scanId, userId).run()).meta.changes ?? 0;
}

// ------------------------------------------------------------------ events & metrics

export type EventType =
  | "scan_created" | "scan_cached" | "stage" | "scan_completed" | "scan_failed" | "scan_refused" | "ssrf_blocked" | "rate_limited" | "user_blocked"
  | "metric" | "share_created" | "share_revoked" | "scan_deleted" | "auth_login" | "auth_login_failed" | "auth_signup" | "auth_throttled";

/** Audit/observability event. `meta` must hold only small scalars — never response content. */
export async function recordEvent(db: D1Like, e: { type: EventType; scanId?: string | null; userId?: string | null; level?: "debug" | "info" | "warn" | "error"; message?: string; meta?: Record<string, string | number | boolean | null> }) {
  log(e.level ?? "info", e.type, { scan: e.scanId ?? undefined, user: e.userId ?? undefined, msg: e.message, ...(e.meta ?? {}) });
  try {
    await db.prepare("INSERT INTO scan_events (scan_id,user_id,type,level,message,meta,created_at) VALUES (?,?,?,?,?,?,?)")
      .bind(e.scanId ?? null, e.userId ?? null, e.type, e.level ?? "info", e.message?.slice(0, 300) ?? null, JSON.stringify(e.meta ?? {}), nowIso()).run();
  } catch {
    log("error", "event_insert_failed", { type: e.type }); // an audit-log failure must never break the request
  }
}
export async function countEvents(db: D1Like, userId: string, type: EventType, windowMs: number): Promise<number> {
  return (await db.prepare("SELECT COUNT(*) c FROM scan_events WHERE user_id = ? AND type = ? AND created_at > ?").bind(userId, type, isoAgo(windowMs)).first<{ c: number }>())?.c ?? 0;
}

export async function metrics(db: D1Like) {
  const hour = isoAgo(HOUR);
  const n = async (sql: string, ...p: string[]) => (await db.prepare(sql).bind(...p).first<{ c: number }>())?.c ?? 0;
  const [queued, completed, failed, refused, blocked, limited, throttled] = await Promise.all([
    n("SELECT COUNT(*) c FROM scans WHERE status='queued'"),
    n("SELECT COUNT(*) c FROM scans WHERE status='completed' AND completed_at > ?", hour),
    n("SELECT COUNT(*) c FROM scan_events WHERE type='scan_failed' AND created_at > ?", hour),
    n("SELECT COUNT(*) c FROM scan_events WHERE type='scan_refused' AND created_at > ?", hour),
    n("SELECT COUNT(*) c FROM scan_events WHERE type='ssrf_blocked' AND created_at > ?", hour),
    n("SELECT COUNT(*) c FROM scan_events WHERE type='rate_limited' AND created_at > ?", hour),
    n("SELECT COUNT(*) c FROM scan_events WHERE type='auth_throttled' AND created_at > ?", hour),
  ]);
  const oldest = await db.prepare("SELECT created_at FROM scans WHERE status='queued' ORDER BY created_at LIMIT 1").first<{ created_at: string }>();
  const { results } = await db.prepare("SELECT meta FROM scan_events WHERE type='scan_completed' AND created_at > ? LIMIT 500").bind(hour).all<{ meta: string }>();
  const lat = results.map((r) => Number(parseJson<{ latency_ms?: number }>(r.meta, {}).latency_ms)).filter(Number.isFinite).sort((a, b) => a - b);
  const pct = (p: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor(lat.length * p))]! : null);
  return {
    queue_depth: queued,
    oldest_queued_age_s: oldest ? Math.round((Date.now() - new Date(oldest.created_at).getTime()) / 1000) : 0,
    last_hour: { completed, failed, refused, ssrf_blocked: blocked, rate_limited: limited, auth_throttled: throttled, error_rate: completed + failed ? Number((failed / (completed + failed)).toFixed(3)) : 0 },
    worker_latency_ms: { p50: pct(0.5), p95: pct(0.95), samples: lat.length },
  };
}

export { isoIn };

/** Put an in-flight scan back on the queue so a retried message can claim it again. */
export const requeueScan = (db: D1Like, id: string) =>
  db.prepare("UPDATE scans SET status = 'queued', locked_at = NULL WHERE id = ? AND status NOT IN ('completed','failed')").bind(id).run();

// ------------------------------------------------------------------ thời lượng sử dụng, chat hỗ trợ, quản trị

const ACTIVITY_THROTTLE_S = 30, ACTIVITY_MAX_GAP_S = 300;

/**
 * Cộng dồn thời gian hoạt động: mỗi yêu cầu có phiên đăng nhập cộng khoảng cách tới lần trước nếu ≤ 5 phút
 * (nghỉ lâu hơn = phiên mới, không tính). Ghi tối đa 1 lần / 30 giây / người dùng để không tốn lượt ghi D1.
 */
export async function touchActivity(db: D1Like, userId: string): Promise<void> {
  const now = nowIso();
  await db.prepare(`UPDATE users SET
      usage_seconds = usage_seconds + CASE WHEN last_seen_at IS NOT NULL AND (julianday(?1) - julianday(last_seen_at)) * 86400 <= ?3
        THEN CAST((julianday(?1) - julianday(last_seen_at)) * 86400 AS INTEGER) ELSE 0 END,
      last_seen_at = ?1
    WHERE id = ?2 AND (last_seen_at IS NULL OR (julianday(?1) - julianday(last_seen_at)) * 86400 >= ?4)`)
    .bind(now, userId, ACTIVITY_MAX_GAP_S, ACTIVITY_THROTTLE_S).run();
}

export const hasGoogleLink = async (db: D1Like, userId: string) =>
  !!(await db.prepare("SELECT 1 x FROM users WHERE id = ? AND google_sub IS NOT NULL").bind(userId).first());

export interface ChatMessage { id: string; sender: "user" | "admin"; body: string; created_at: string; read_at: string | null }
export const CHAT_MAX_LEN = 1000;

export async function sendChat(db: D1Like, userId: string, sender: "user" | "admin", body: string): Promise<ChatMessage> {
  const m: ChatMessage = { id: newId(), sender, body: body.slice(0, CHAT_MAX_LEN), created_at: nowIso(), read_at: null };
  await db.prepare("INSERT INTO chat_messages (id,user_id,sender,body,created_at) VALUES (?,?,?,?,?)").bind(m.id, userId, sender, m.body, m.created_at).run();
  return m;
}
export async function listChat(db: D1Like, userId: string, limit = 200): Promise<ChatMessage[]> {
  const { results } = await db.prepare("SELECT id,sender,body,created_at,read_at FROM (SELECT * FROM chat_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT ?) ORDER BY created_at ASC")
    .bind(userId, limit).all<ChatMessage>();
  return results;
}
/** Đánh dấu đã đọc các tin của PHÍA KIA (reader = người đang xem). */
export const markChatRead = (db: D1Like, userId: string, reader: "user" | "admin") =>
  db.prepare("UPDATE chat_messages SET read_at = ? WHERE user_id = ? AND sender = ? AND read_at IS NULL").bind(nowIso(), userId, reader === "user" ? "admin" : "user").run();
export const countChatSince = async (db: D1Like, userId: string, sender: "user" | "admin", since: string) =>
  (await db.prepare("SELECT COUNT(*) c FROM chat_messages WHERE user_id = ? AND sender = ? AND created_at > ?").bind(userId, sender, since).first<{ c: number }>())?.c ?? 0;
export const unreadAdminReplies = async (db: D1Like, userId: string) =>
  (await db.prepare("SELECT COUNT(*) c FROM chat_messages WHERE user_id = ? AND sender = 'admin' AND read_at IS NULL").bind(userId).first<{ c: number }>())?.c ?? 0;

export interface AdminOverview { users: number; activeToday: number; scansTotal: number; scans24h: number; unreadChats: number; usageSecondsTotal: number }
export async function adminOverview(db: D1Like): Promise<AdminOverview> {
  const day = isoAgo(DAY);
  const one = async (sql: string, ...p: string[]) => (await db.prepare(sql).bind(...p).first<{ c: number }>())?.c ?? 0;
  const [users, activeToday, scansTotal, scans24h, unreadChats, usageSecondsTotal] = await Promise.all([
    one("SELECT COUNT(*) c FROM users"),
    one("SELECT COUNT(*) c FROM users WHERE last_seen_at > ?", day),
    one("SELECT COUNT(*) c FROM scans"),
    one("SELECT COUNT(*) c FROM scans WHERE created_at > ?", day),
    one("SELECT COUNT(DISTINCT user_id) c FROM chat_messages WHERE sender='user' AND read_at IS NULL"),
    one("SELECT COALESCE(SUM(usage_seconds),0) c FROM users"),
  ]);
  return { users, activeToday, scansTotal, scans24h, unreadChats, usageSecondsTotal };
}

export interface AdminUserRow { id: string; email: string; display_name: string | null; created_at: string; last_seen_at: string | null; usage_seconds: number; scan_count: number; last_scan_at: string | null; unread: number; blocked_until: string | null }
export async function adminListUsers(db: D1Like, limit = 200): Promise<AdminUserRow[]> {
  const { results } = await db.prepare(`
    SELECT u.id, u.email, u.display_name, u.created_at, u.last_seen_at, u.usage_seconds, u.blocked_until,
      (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scan_count,
      (SELECT MAX(created_at) FROM scans s WHERE s.user_id = u.id) AS last_scan_at,
      (SELECT COUNT(*) FROM chat_messages c WHERE c.user_id = u.id AND c.sender = 'user' AND c.read_at IS NULL) AS unread
    FROM users u ORDER BY unread DESC, COALESCE(u.last_seen_at, u.created_at) DESC LIMIT ?`).bind(limit).all<AdminUserRow>();
  return results;
}
export const adminGetUser = (db: D1Like, id: string) =>
  db.prepare("SELECT id,email,display_name,created_at,last_seen_at,usage_seconds,blocked_until FROM users WHERE id = ?").bind(id)
    .first<Pick<AdminUserRow, "id" | "email" | "display_name" | "created_at" | "last_seen_at" | "usage_seconds" | "blocked_until">>();
export async function adminUserScans(db: D1Like, userId: string, limit = 100) {
  const { results } = await db.prepare("SELECT id,normalized_url,status,score,grade,created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?").bind(userId, limit)
    .all<{ id: string; normalized_url: string; status: string; score: number | null; grade: string | null; created_at: string }>();
  return results;
}

export const CACHE_TTL_OTHERS_MS = 6 * HOUR, CACHE_TTL_OWN_MS = 15 * 60_000, CACHE_CLONES_PER_HOUR = 20;

/**
 * Dùng lại kết quả quét hoàn tất gần đây của CÙNG URL thay vì chạy lại container.
 * Của người khác: ≤ 6 giờ. Của chính mình: chỉ ≤ 15 phút (để quét lại sau khi sửa lỗi luôn là quét thật).
 * Bản sao thuộc về người gọi, tuân thủ thời hạn lưu trữ của họ và KHÔNG tính vào hạn mức.
 */
export async function cloneRecentScan(db: D1Like, a: { userId: string; url: string; host: string; ipHash: string | null; mode?: ScanMode }): Promise<string | null> {
  const src = await db.prepare(`SELECT id FROM scans WHERE normalized_url = ? AND status = 'completed' AND cached = 0 AND (mode = 'full' OR ? = 'quick') AND (
      (user_id <> ? AND completed_at > ?) OR (user_id = ? AND completed_at > ?)) ORDER BY completed_at DESC LIMIT 1`)
    .bind(a.url, a.mode ?? "full", a.userId, isoAgo(CACHE_TTL_OTHERS_MS), a.userId, isoAgo(CACHE_TTL_OWN_MS)).first<{ id: string }>();
  if (!src) return null;
  const recent = (await db.prepare("SELECT COUNT(*) c FROM scans WHERE user_id = ? AND cached = 1 AND created_at > ?").bind(a.userId, isoAgo(HOUR)).first<{ c: number }>())?.c ?? 0;
  if (recent >= CACHE_CLONES_PER_HOUR) return null; // quá nhiều → rơi về luồng quét thật (có hạn mức)
  const u = await getUserById(db, a.userId);
  const id = newId(), now = nowIso();
  const expires = new Date(Date.now() + (u?.retention_days ?? 30) * DAY).toISOString();
  const rid = "lower(hex(randomblob(16)))";
  await db.batch([
    db.prepare(`INSERT INTO scans (id,user_id,input_url,normalized_url,host,ip_hash,status,score,grade,category_scores,severity_counts,platforms,request_count,cached,created_at,started_at,completed_at,expires_at,mode)
      SELECT ?,?,normalized_url,normalized_url,host,?,'completed',score,grade,category_scores,severity_counts,platforms,0,1,?,?,?,?,mode FROM scans WHERE id = ?`)
      .bind(id, a.userId, a.ipHash, now, now, now, expires, src.id),
    db.prepare(`INSERT INTO findings (id,scan_id,rule_id,fingerprint,title,category,severity,confidence,status,evidence,explanation,summary,technical,remediation,affected_url,refs)
      SELECT ${rid},?,rule_id,fingerprint,title,category,severity,confidence,status,evidence,explanation,summary,technical,remediation,affected_url,refs FROM findings WHERE scan_id = ?`).bind(id, src.id),
    db.prepare(`INSERT INTO scan_targets (id,scan_id,role,url,final_url,status_code,tls,headers_enc,resolved_ips,error_code,duration_ms,created_at)
      SELECT ${rid},?,role,url,final_url,status_code,tls,headers_enc,resolved_ips,error_code,duration_ms,? FROM scan_targets WHERE scan_id = ?`).bind(id, now, src.id),
  ]);
  return id;
}
export const userBlocked = async (db: D1Like, userId: string) => {
  const u = await getUserById(db, userId);
  return !!(u?.blocked_until && u.blocked_until > nowIso());
};

// ------------------------------------------------------------------ bộ nhớ đệm TLS (tránh đánh thức container)

export const TLS_CACHE_TTL_MS = 12 * HOUR;
export async function getTlsCache<T>(db: D1Like, host: string): Promise<T | null> {
  const r = await db.prepare("SELECT data FROM tls_cache WHERE host = ? AND fetched_at > ?").bind(host, isoAgo(TLS_CACHE_TTL_MS)).first<{ data: string }>();
  return r ? parseJson<T | null>(r.data, null) : null;
}
export const putTlsCache = (db: D1Like, host: string, data: unknown) =>
  db.prepare("INSERT INTO tls_cache (host,data,fetched_at) VALUES (?,?,?) ON CONFLICT(host) DO UPDATE SET data=excluded.data, fetched_at=excluded.fetched_at").bind(host, JSON.stringify(data), nowIso()).run();
