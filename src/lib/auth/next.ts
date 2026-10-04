import { cookies } from "next/headers";
import { getDb } from "../cf";
import { env } from "../env";
import { resolveSession, SESSION_TTL_MS } from "./core";

/** `__Host-` prefix pins the cookie to this origin/path and requires Secure — enabled in production only (localhost is http). */
export const SESSION_COOKIE = env.isProd ? "__Host-vs_session" : "vs_session";

export function sessionCookieOptions(expiresAt?: string) {
  return { httpOnly: true, secure: env.isProd, sameSite: "lax" as const, path: "/", ...(expiresAt ? { expires: new Date(expiresAt) } : { maxAge: SESSION_TTL_MS / 1000 }) };
}

export interface SessionUser { id: string; email: string; retention_days: number }

/** Current user from the session cookie, or null. Never throws (pages must render when bindings are unavailable). */
export async function getUser(): Promise<SessionUser | null> {
  try {
    const token = (await cookies()).get(SESSION_COOKIE)?.value;
    if (!token) return null;
    return await resolveSession(await getDb(), token);
  } catch {
    return null;
  }
}
