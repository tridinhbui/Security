/** Cloudflare Turnstile server-side verification. No-ops (passes) when TURNSTILE_SECRET_KEY is not configured. */
export async function verifyTurnstile(secret: string | null, token: string | undefined, ip: string | null, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  if (!secret) return true;
  if (!token) return false;
  try {
    const body = new FormData();
    body.set("secret", secret);
    body.set("response", token);
    if (ip) body.set("remoteip", ip);
    const res = await fetchImpl("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body, signal: AbortSignal.timeout(5000) });
    return ((await res.json()) as { success?: boolean }).success === true;
  } catch {
    return false; // fail closed
  }
}
