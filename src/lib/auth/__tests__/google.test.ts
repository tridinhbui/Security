import { randomBytes } from "node:crypto";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { encrypt, toB64Url } from "@/lib/crypto";
import { createTestD1 } from "@/lib/db/__tests__/test-d1";
import * as repo from "@/lib/db/repo";
import { resolveSession } from "../core";
import { buildAuthUrl, challengeFor, exchangeCode, GoogleAuthError, pkcePair, verifyGoogleIdToken, type JwksFetcher } from "../google";
import { finishGoogleLogin, OAUTH_TTL_MS, redirectUriFor, safeNext, startGoogleLogin, type OAuthState } from "../google-flow";
import { verifyPassword } from "../password";

const CLIENT = "123-abc.apps.googleusercontent.com";
const enc = new TextEncoder();
const b64 = (o: object) => toB64Url(enc.encode(JSON.stringify(o)));

let keyPair: CryptoKeyPair, otherKey: CryptoKeyPair, jwk: JsonWebKey;
const jwks: JwksFetcher = async () => [{ ...jwk, kid: "k1" }];

async function sign(payload: object, o: { kid?: string; alg?: string; key?: CryptoKeyPair } = {}) {
  const header = b64({ alg: o.alg ?? "RS256", kid: o.kid ?? "k1", typ: "JWT" });
  const body = b64(payload);
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", (o.key ?? keyPair).privateKey, enc.encode(`${header}.${body}`)));
  return `${header}.${body}.${toB64Url(sig)}`;
}
const claims = (over: object = {}) => ({ iss: "https://accounts.google.com", aud: CLIENT, sub: "g-123", email: "User@Example.com", email_verified: true, name: "Nguyễn Văn A", picture: "https://lh3.googleusercontent.com/a/x", nonce: "N1", exp: Math.floor(Date.now() / 1000) + 600, iat: Math.floor(Date.now() / 1000) - 5, ...over });

beforeAll(async () => {
  const gen = () => crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
  keyPair = await gen(); otherKey = await gen();
  jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  Object.assign(process.env, { DATA_ENCRYPTION_KEY: randomBytes(32).toString("base64"), IP_HASH_SECRET: "s", GOOGLE_CLIENT_ID: CLIENT, GOOGLE_CLIENT_SECRET: "top-secret-value", NEXT_PUBLIC_SITE_URL: "https://vibesec.example.org" });
});

describe("PKCE & URL", () => {
  it("challenge đúng vector chuẩn RFC 7636", async () => {
    expect(await challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
  it("verifier ngẫu nhiên, đủ dài, không lặp", async () => {
    const a = await pkcePair(), b = await pkcePair();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.verifier.length).toBeGreaterThanOrEqual(43);
    expect(a.challenge).toBe(await challengeFor(a.verifier));
  });
  it("URL uỷ quyền có S256, state, nonce, scope tối thiểu và KHÔNG chứa client secret", () => {
    const u = new URL(buildAuthUrl({ clientId: CLIENT, redirectUri: "https://x.y/cb", state: "S", nonce: "N", codeChallenge: "C" }));
    expect(u.origin + u.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(Object.fromEntries(u.searchParams)).toMatchObject({ client_id: CLIENT, response_type: "code", scope: "openid email profile", state: "S", nonce: "N", code_challenge: "C", code_challenge_method: "S256" });
    expect(u.toString()).not.toContain("secret");
  });
});

describe("verifyGoogleIdToken", () => {
  const v = (t: string, over: object = {}) => verifyGoogleIdToken(t, { clientId: CLIENT, nonce: "N1", jwks, ...over });
  it("chấp nhận token hợp lệ, chuẩn hoá email, giữ hồ sơ", async () => {
    expect(await v(await sign(claims()))).toEqual({ sub: "g-123", email: "user@example.com", name: "Nguyễn Văn A", picture: "https://lh3.googleusercontent.com/a/x" });
  });
  it("chấp nhận issuer không có scheme và aud dạng mảng", async () => {
    expect((await v(await sign(claims({ iss: "accounts.google.com", aud: ["other", CLIENT] })))).sub).toBe("g-123");
  });
  it.each([
    ["sai chữ ký (khoá khác)", async () => sign(claims(), { key: otherKey })],
    ["alg=none", async () => `${b64({ alg: "none", kid: "k1" })}.${b64(claims())}.`],
    ["đổi thuật toán sang HS256", async () => sign(claims(), { alg: "HS256" })],
    ["kid không tồn tại", async () => sign(claims(), { kid: "zzz" })],
    ["sai audience", async () => sign(claims({ aud: "evil.apps.googleusercontent.com" }))],
    ["sai issuer", async () => sign(claims({ iss: "https://evil.example" }))],
    ["hết hạn", async () => sign(claims({ exp: Math.floor(Date.now() / 1000) - 3600 }))],
    ["iat ở tương lai", async () => sign(claims({ iat: Math.floor(Date.now() / 1000) + 3600 }))],
    ["sai nonce (replay)", async () => sign(claims({ nonce: "OTHER" }))],
    ["thiếu nonce", async () => sign(claims({ nonce: undefined }))],
    ["thiếu sub", async () => sign(claims({ sub: "" }))],
    ["token rác", async () => "a.b"],
    ["token quá dài", async () => "x".repeat(5000)],
  ])("từ chối: %s", async (_n, make) => {
    await expect(v(await make())).rejects.toMatchObject({ code: "invalid_token" });
  });
  it("từ chối email chưa xác minh bằng mã riêng", async () => {
    await expect(v(await sign(claims({ email_verified: false })))).rejects.toMatchObject({ code: "email_unverified" });
    await expect(v(await sign(claims({ email_verified: "true" })))).rejects.toMatchObject({ code: "email_unverified" }); // chuỗi không phải boolean
  });
  it("bỏ qua ảnh không phải https và tên quá dài (không tin dữ liệu từ ngoài)", async () => {
    const r = await v(await sign(claims({ picture: "http://x/y.png", name: "A".repeat(500) })));
    expect(r.picture).toBeNull();
    expect(r.name).toBeNull();
  });
  it("thử lấy lại JWKS khi khoá vừa xoay", async () => {
    const calls: boolean[] = [];
    const rotating: JwksFetcher = async (force) => (calls.push(force), force ? [{ ...jwk, kid: "k1" }] : []);
    expect((await v(await sign(claims()), { jwks: rotating })).sub).toBe("g-123");
    expect(calls).toEqual([false, true]);
  });
});

describe("exchangeCode", () => {
  const args = { code: "C", verifier: "V", clientId: CLIENT, clientSecret: "top-secret-value", redirectUri: "https://x/cb" };
  it("gửi đúng tham số (kèm code_verifier) và trả id_token", async () => {
    const f = vi.fn(async (_u: unknown, init?: RequestInit) => {
      const p = new URLSearchParams(String(init!.body));
      expect(Object.fromEntries(p)).toMatchObject({ grant_type: "authorization_code", code: "C", code_verifier: "V", client_id: CLIENT, redirect_uri: "https://x/cb" });
      return Response.json({ id_token: "T" });
    });
    expect(await exchangeCode(args, f as never)).toBe("T");
  });
  it("lỗi từ Google/mạng/thiếu id_token → token_exchange, không lộ nội dung lỗi", async () => {
    for (const f of [async () => new Response("secret-detail", { status: 400 }), async () => { throw new Error("net secret"); }, async () => Response.json({})]) {
      const e = await exchangeCode(args, f as never).catch((x) => x);
      expect(e).toBeInstanceOf(GoogleAuthError);
      expect(e.code).toBe("token_exchange");
      expect(String(e.message)).not.toContain("secret");
    }
  });
});

describe("safeNext & redirect URI", () => {
  it.each([["/dashboard", "/dashboard"], ["/scans/1?x=2", "/scans/1?x=2"], ["//evil.com", "/dashboard"], ["https://evil.com", "/dashboard"], ["/\\evil.com", "/dashboard"], ["/a\r\nSet-Cookie: x", "/dashboard"], [null, "/dashboard"], ["", "/dashboard"]])("%j → %s", (i, o) => expect(safeNext(i as string | null)).toBe(o));
  it("production dùng SITE_URL cố định; chỉ localhost được dùng origin thật", () => {
    expect(redirectUriFor("https://evil.attacker.net")).toBe("https://vibesec.example.org/api/auth/google/callback");
    expect(redirectUriFor("http://localhost:8787")).toBe("http://localhost:8787/api/auth/google/callback");
  });
});

describe("luồng đăng nhập đầy đủ (D1 thật)", () => {
  let db: ReturnType<typeof createTestD1>;
  beforeEach(() => { db = createTestD1(); });

  async function begin() {
    const { cookie, location } = await startGoogleLogin({ next: "/scans", requestOrigin: "http://localhost:8787" });
    const u = new URL(location);
    return { cookie, state: u.searchParams.get("state")!, nonce: u.searchParams.get("nonce")! };
  }
  const tokenFetch = (idToken: string) => (async () => Response.json({ id_token: idToken })) as unknown as typeof fetch;
  const finish = (a: Partial<Parameters<typeof finishGoogleLogin>[0]>, idToken = "x") =>
    finishGoogleLogin({ code: "code", state: "s", error: null, cookie: undefined, requestOrigin: "http://localhost:8787", ipHash: "ip1", ...a }, { db, fetchImpl: tokenFetch(idToken), jwks });

  it("tạo tài khoản mới, mở phiên và trả về đường dẫn đã chọn", async () => {
    const b = await begin();
    const r = await finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: b.nonce })));
    expect(r.next).toBe("/scans");
    const u = (await resolveSession(db, r.token))!;
    expect(u).toMatchObject({ email: "user@example.com", name: "Nguyễn Văn A" });
    const row = (await repo.getUserById(db, u.id))!;
    expect(row.google_sub).toBe("g-123");
    expect(await verifyPassword("bat-ky-mat-khau", row.password_hash)).toBe(false); // không thể đăng nhập bằng mật khẩu
  });
  it("liên kết vào tài khoản mật khẩu sẵn có cùng email (không tạo bản sao)", async () => {
    const existing = await repo.createUser(db, "user@example.com", "scrypt$x"); if (!existing.ok) throw new Error();
    const b = await begin();
    const r = await finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: b.nonce })));
    expect(r.userId).toBe(existing.id);
    expect((db.sqlite.prepare("SELECT COUNT(*) c FROM users").get() as { c: number }).c).toBe(1);
    expect((await repo.getUserById(db, existing.id))!.password_hash).toBe("scrypt$x"); // mật khẩu cũ giữ nguyên
  });
  it("đăng nhập lần hai cập nhật hồ sơ và dùng lại cùng tài khoản", async () => {
    const b1 = await begin();
    const r1 = await finish({ state: b1.state, cookie: b1.cookie }, await sign(claims({ nonce: b1.nonce })));
    const b2 = await begin();
    const r2 = await finish({ state: b2.state, cookie: b2.cookie }, await sign(claims({ nonce: b2.nonce, name: "Tên mới", email: "doi-email@example.com" })));
    expect(r2.userId).toBe(r1.userId);
    expect((await repo.getUserById(db, r1.userId))!.display_name).toBe("Tên mới");
  });
  it.each([
    ["state sai (CSRF đăng nhập)", async (b: Awaited<ReturnType<typeof begin>>) => ({ state: "KHAC", cookie: b.cookie }), "state_mismatch"],
    ["thiếu cookie", async (b: Awaited<ReturnType<typeof begin>>) => ({ state: b.state, cookie: undefined }), "state_mismatch"],
    ["cookie bị sửa", async (b: Awaited<ReturnType<typeof begin>>) => ({ state: b.state, cookie: b.cookie.slice(0, -4) + "AAAA" }), "state_mismatch"],
    ["người dùng bấm Từ chối", async (b: Awaited<ReturnType<typeof begin>>) => ({ state: b.state, cookie: b.cookie, error: "access_denied", code: null }), "access_denied"],
  ])("từ chối: %s", async (_n, mk, code) => {
    const b = await begin();
    await expect(finish(await mk(b), await sign(claims({ nonce: b.nonce })))).rejects.toMatchObject({ code });
    expect((db.sqlite.prepare("SELECT COUNT(*) c FROM users").get() as { c: number }).c).toBe(0);
  });
  it("state hết hạn", async () => {
    const b = await begin();
    const old: OAuthState = { s: b.state, n: b.nonce, v: "v", x: "/", t: Date.now() - OAUTH_TTL_MS - 5000 };
    await expect(finish({ state: b.state, cookie: await encrypt(JSON.stringify(old)) }, await sign(claims({ nonce: b.nonce })))).rejects.toMatchObject({ code: "state_expired" });
  });
  it("id_token sai nonce / email chưa xác minh bị từ chối và không tạo người dùng", async () => {
    const b = await begin();
    await expect(finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: "SAI" })))).rejects.toMatchObject({ code: "invalid_token" });
    await expect(finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: b.nonce, email_verified: false })))).rejects.toMatchObject({ code: "email_unverified" });
    expect((db.sqlite.prepare("SELECT COUNT(*) c FROM users").get() as { c: number }).c).toBe(0);
  });
  it("tài khoản đang bị khoá không đăng nhập được bằng Google", async () => {
    const u = await repo.createUser(db, "user@example.com", "scrypt$x"); if (!u.ok) throw new Error();
    await repo.blockUser(db, u.id, new Date(Date.now() + 86_400_000).toISOString());
    const b = await begin();
    await expect(finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: b.nonce })))).rejects.toMatchObject({ code: "blocked" });
  });
  it("giới hạn thất bại theo IP", async () => {
    process.env.AUTH_OAUTH_FAILS_PER_IP = "3";
    for (let i = 0; i < 3; i++) await finish({ state: "x", cookie: undefined }).catch(() => {});
    const b = await begin();
    await expect(finish({ state: b.state, cookie: b.cookie }, await sign(claims({ nonce: b.nonce })))).rejects.toMatchObject({ code: "throttled" });
    delete process.env.AUTH_OAUTH_FAILS_PER_IP;
  });
  it("không cấu hình thì từ chối rõ ràng (không giả lập đăng nhập)", async () => {
    const save = process.env.GOOGLE_CLIENT_SECRET; delete process.env.GOOGLE_CLIENT_SECRET;
    await expect(startGoogleLogin({ next: null, requestOrigin: "http://localhost" })).rejects.toMatchObject({ code: "not_configured" });
    process.env.GOOGLE_CLIENT_SECRET = save;
  });
  it("cookie OAuth không chứa code_verifier ở dạng đọc được", async () => {
    const b = await begin();
    expect(b.cookie.startsWith("v1:")).toBe(true);
    expect(atob(b.cookie.split(":")[2]!.replace(/-/g, "+"))).not.toContain(b.state);
  });
});
