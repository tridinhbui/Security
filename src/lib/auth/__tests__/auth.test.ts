import { randomBytes } from "node:crypto";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createTestD1 } from "@/lib/db/__tests__/test-d1";
import * as repo from "@/lib/db/repo";
import { login, logout, resolveSession, signup } from "../core";
import { hashPassword, validateCredentials, verifyPassword } from "../password";
import { verifyTurnstile } from "../turnstile";

beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("base64");
  process.env.IP_HASH_SECRET = "s3cret";
});
let db: ReturnType<typeof createTestD1>;
beforeEach(() => { db = createTestD1(); });
const PW = "correct horse battery";

describe("password hashing", () => {
  it("round-trips, salts, and rejects wrong passwords", async () => {
    const a = await hashPassword(PW), b = await hashPassword(PW);
    expect(a).not.toBe(b);
    expect(a.startsWith("scrypt$32768$8$3$")).toBe(true);
    expect(await verifyPassword(PW, a)).toBe(true);
    expect(await verifyPassword(PW + "x", a)).toBe(false);
    expect(await verifyPassword("", a)).toBe(false);
  });
  it("NFKC-normalises and rejects malformed or absurd-cost hashes", async () => {
    expect(await verifyPassword("ﬁsh-password-1", await hashPassword("fish-password-1"))).toBe(true);
    expect(await verifyPassword(PW, "garbage")).toBe(false);
    expect(await verifyPassword(PW, "scrypt$4294967296$8$3$AAAA$AAAA")).toBe(false); // DoS via stored cost
  });
});

describe("credential validation", () => {
  it.each([["a@b.co", PW, true], ["  A@B.CO ", PW, true], ["nope", PW, false], ["a@b", PW, false], ["a b@c.com", PW, false], ["a@b.co", "short", false], ["a@b.co", "password123", false], ["alice@x.com", "alice-is-me-123", false], ["a@b.co", "x".repeat(200), false]])(
    "%j / %j → %s", (e, p, ok) => expect(validateCredentials(e, p).ok).toBe(ok));
});

describe("signup / login / session", () => {
  const ip = "iphash-1";
  it("signs up, stores a hashed password, and starts a session", async () => {
    const r = await signup(db, { email: "New@Example.com", password: PW, ipHash: ip });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const u = (await repo.getUserByEmail(db, "new@example.com"))!;
    expect(u.password_hash).not.toContain(PW);
    expect((await resolveSession(db, r.token))!.email).toBe("new@example.com");
    // the cookie token is not what's stored
    expect((db.sqlite.prepare("SELECT id FROM sessions").get() as { id: string }).id).not.toBe(r.token);
  });
  it("rejects duplicate emails and invalid input", async () => {
    await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    expect(await signup(db, { email: "a@b.co", password: PW, ipHash: ip })).toMatchObject({ ok: false, status: 409 });
    expect(await signup(db, { email: "bad", password: PW, ipHash: ip })).toMatchObject({ ok: false, status: 400 });
  });
  it("throttles signups per IP", async () => {
    process.env.AUTH_SIGNUPS_PER_IP_HOUR = "2";
    for (let i = 0; i < 2; i++) expect((await signup(db, { email: `u${i}@x.com`, password: PW, ipHash: "ipS" })).ok).toBe(true);
    expect(await signup(db, { email: "u9@x.com", password: PW, ipHash: "ipS" })).toMatchObject({ ok: false, status: 429 });
    delete process.env.AUTH_SIGNUPS_PER_IP_HOUR;
  });
  it("logs in with the right password; wrong password and unknown email give the same answer", async () => {
    await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    expect((await login(db, { email: "A@B.co", password: PW, ipHash: ip })).ok).toBe(true);
    const bad = await login(db, { email: "a@b.co", password: "nope-nope-nope", ipHash: ip });
    const unknown = await login(db, { email: "ghost@b.co", password: "nope-nope-nope", ipHash: ip });
    expect(bad).toMatchObject({ ok: false, status: 401 });
    expect(unknown).toEqual(bad); // no user enumeration
  });
  it("throttles after repeated failures per email (and success is still blocked while throttled)", async () => {
    await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    for (let i = 0; i < 5; i++) await login(db, { email: "a@b.co", password: "wrong-wrong-wrong", ipHash: `rot${i}` });
    expect(await login(db, { email: "a@b.co", password: PW, ipHash: "other" })).toMatchObject({ ok: false, status: 429 });
  });
  it("throttles per IP across emails", async () => {
    process.env.AUTH_LOGIN_FAILS_PER_IP = "3";
    for (let i = 0; i < 3; i++) await login(db, { email: `x${i}@b.co`, password: "wrong-wrong-wrong", ipHash: "ipA" });
    expect(await login(db, { email: "fresh@b.co", password: "wrong-wrong-wrong", ipHash: "ipA" })).toMatchObject({ status: 429 });
    delete process.env.AUTH_LOGIN_FAILS_PER_IP;
  });
  it("a successful login clears the email's failure counter", async () => {
    await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    for (let i = 0; i < 3; i++) await login(db, { email: "a@b.co", password: "wrong-wrong-wrong", ipHash: ip });
    expect((await login(db, { email: "a@b.co", password: PW, ipHash: ip })).ok).toBe(true);
    expect((db.sqlite.prepare("SELECT COUNT(*) c FROM auth_attempts WHERE kind='login_fail_email'").get() as { c: number }).c).toBe(0);
  });
  it("logout invalidates the session; garbage tokens resolve to nothing", async () => {
    const r = await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    if (!r.ok) throw new Error();
    await logout(db, r.token);
    expect(await resolveSession(db, r.token)).toBeNull();
    for (const t of [undefined, null, "", "short", "x".repeat(500)]) expect(await resolveSession(db, t)).toBeNull();
  });
  it("expired sessions are rejected; sessions past half-life are extended", async () => {
    const r = await signup(db, { email: "a@b.co", password: PW, ipHash: ip });
    if (!r.ok) throw new Error();
    db.sqlite.prepare("UPDATE sessions SET expires_at = ?").run(new Date(Date.now() + 5 * 86_400_000).toISOString());
    expect(await resolveSession(db, r.token)).not.toBeNull();
    const row = db.sqlite.prepare("SELECT expires_at FROM sessions").get() as { expires_at: string };
    expect(Date.parse(row.expires_at) - Date.now()).toBeGreaterThan(25 * 86_400_000);
    db.sqlite.prepare("UPDATE sessions SET expires_at = ?").run(new Date(Date.now() - 1000).toISOString());
    expect(await resolveSession(db, r.token)).toBeNull();
  });
  it("never stores raw email or IP in the throttling table", async () => {
    await login(db, { email: "secret.person@x.com", password: "wrong-wrong-wrong", ipHash: "1.2.3.4" });
    const rows = JSON.stringify(db.sqlite.prepare("SELECT * FROM auth_attempts").all());
    expect(rows).not.toContain("secret.person");
    expect(rows).not.toContain("1.2.3.4");
  });
});

describe("Turnstile", () => {
  it("passes when not configured, fails closed otherwise", async () => {
    expect(await verifyTurnstile(null, undefined, null)).toBe(true);
    expect(await verifyTurnstile("sec", undefined, null)).toBe(false);
    expect(await verifyTurnstile("sec", "tok", "1.1.1.1", vi.fn(async () => Response.json({ success: true })) as never)).toBe(true);
    expect(await verifyTurnstile("sec", "tok", null, vi.fn(async () => Response.json({ success: false })) as never)).toBe(false);
    expect(await verifyTurnstile("sec", "tok", null, vi.fn(async () => { throw new Error("net"); }) as never)).toBe(false);
  });
});
