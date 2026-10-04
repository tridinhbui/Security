/**
 * Structured JSON logging for observability. Deliberately has no way to log bodies:
 * callers pass small typed fields only, and long strings are truncated.
 */
type Level = "debug" | "info" | "warn" | "error";

export function log(level: Level, event: string, fields: Record<string, string | number | boolean | null | undefined> = {}) {
  const safe: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) safe[k] = typeof v === "string" && v.length > 200 ? v.slice(0, 200) + "…" : v;
  const line = JSON.stringify({ t: new Date().toISOString(), level, event, ...safe });
  (level === "error" ? console.error : level === "warn" ? console.warn : console.log)(line);
}
