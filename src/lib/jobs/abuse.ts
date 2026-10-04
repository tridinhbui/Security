import type { D1Like } from "../db/d1";
import { isoIn } from "../db/d1";
import * as repo from "../db/repo";
import { env } from "../env";

const BLOCK_MS = 24 * 3_600_000;

/**
 * Records an SSRF/abuse strike and suspends the account after repeated attempts.
 * A user repeatedly pointing the scanner at internal addresses is probing for SSRF.
 */
export async function recordSsrfStrike(db: D1Like, userId: string, ctx: { code: string; stage: "input" | "dns" | "redirect"; host?: string }) {
  await repo.recordEvent(db, { type: "ssrf_blocked", userId, level: "warn", message: `blocked:${ctx.code}`, meta: { code: ctx.code, stage: ctx.stage, host: ctx.host?.slice(0, 120) ?? null } });
  const strikes = await repo.countEvents(db, userId, "ssrf_blocked", 3_600_000);
  if (strikes >= env.limits.ssrfStrikeThreshold) {
    const until = isoIn(BLOCK_MS);
    await repo.blockUser(db, userId, until);
    await repo.recordEvent(db, { type: "user_blocked", userId, level: "error", message: "Repeated blocked scan targets", meta: { strikes, until } });
    return { blocked: true as const, until };
  }
  return { blocked: false as const };
}
