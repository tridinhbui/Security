import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { createTestD1, seedUser } from "@/lib/db/__tests__/test-d1";
import { getProjectScan, insertProjectScan, latestByLabel } from "@/lib/db/project-repo";
import { analyzeSource } from "../code-analyze";
import { findVulns, parseManifests, vulnItems } from "../deps";
import { fetchRepoSnapshot, parseRepoInput } from "../github";
import { compareLaunch, evaluateLaunch } from "../launch";
import { scanFirebase, scanSupabase, SystemScanError } from "../system-scan";
import { item, scoreItems } from "../types";

function tar(files: Record<string, string>): Uint8Array {
  const blocks: Buffer[] = [];
  for (const [name, body] of Object.entries(files)) {
    const h = Buffer.alloc(512);
    h.write(`repo-abc/${name}`, 0); h.write("0000644\0", 100); h.write(body.length.toString(8).padStart(11, "0") + "\0", 124); h.write("0", 156); h.write("ustar\0", 257);
    blocks.push(h, Buffer.from(body), Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}
const respond = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });

// Chuỗi giống khoá thật, ghép lúc chạy để không kích hoạt bộ quét bí mật trên chính file test.
const STRIPE = ["sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("_");

describe("parseRepoInput", () => {
  it("chấp nhận nhiều dạng và từ chối giá trị lạ", () => {
    expect(parseRepoInput("https://github.com/a/b.git")).toEqual({ owner: "a", repo: "b" });
    expect(parseRepoInput("github.com/a/b/tree/main")).toEqual({ owner: "a", repo: "b" });
    expect(parseRepoInput("a/b")).toEqual({ owner: "a", repo: "b" });
    expect(parseRepoInput("http://evil.com/a/b")).toBeNull();
    expect(parseRepoInput("../etc")).toBeNull();
  });
});

describe("fetchRepoSnapshot + tar", () => {
  it("đọc tarball, bỏ thư mục gốc, bỏ node_modules", async () => {
    const buf = tar({ "src/a.ts": "export const a = 1;", "node_modules/x/i.js": "x", ".env": "A=1" });
    const snap = await fetchRepoSnapshot("a", "b", null, (async () => new Response(buf as unknown as BodyInit)) as typeof fetch);
    expect(snap.files.map((f) => f.path).sort()).toEqual([".env", "src/a.ts"]);
    expect(snap.allPaths).not.toContain("node_modules/x/i.js");
  });
  it("báo lỗi 404 thân thiện", async () => {
    await expect(fetchRepoSnapshot("a", "b", null, (async () => new Response("", { status: 404 })) as typeof fetch)).rejects.toMatchObject({ code: "not_found" });
  });
});

describe("analyzeSource", () => {
  it("phát hiện secret nhưng KHÔNG bao giờ lộ giá trị đầy đủ", () => {
    const files = [{ path: "src/pay.ts", content: `const k = "${STRIPE}";\n` }, { path: ".env", content: `DATABASE_URL=postgres://u:realpass123@db.example.org/x\nOPENAI=abcdefghij1234\n` }];
    const items = analyzeSource({ files, allPaths: files.map((f) => f.path) });
    const blob = JSON.stringify(items);
    expect(blob).not.toContain(STRIPE);
    expect(blob).not.toContain("realpass123");
    expect(items.find((i) => i.id === "secret-stripe-live-secret")).toMatchObject({ status: "fail", severity: "critical" });
    expect(items.find((i) => i.id === "secret-stripe-live-secret")!.evidence[0]).toContain("src/pay.ts:1");
    expect(items.find((i) => i.id === "env-file-committed")).toMatchObject({ status: "fail" });
  });
  it("phát hiện mẫu code nguy hiểm và pass khi sạch", () => {
    const bad = [{ path: "a.js", content: "el.innerHTML = x;\ndb.query(`SELECT * FROM t WHERE id=${id}`);\nfetch(u,{agent:{rejectUnauthorized:false}})" }];
    const items = analyzeSource({ files: bad, allPaths: ["a.js"] });
    for (const id of ["code-html-injection", "code-sql-concat", "code-tls-off"]) expect(items.find((i) => i.id === id)?.status).toBe("fail");
    const clean = analyzeSource({ files: [{ path: "a.js", content: "const a = 1;" }], allPaths: ["a.js"] });
    expect(clean.some((i) => i.status === "fail")).toBe(false);
    expect(clean.some((i) => i.id === "secrets-clean")).toBe(true);
  });
  it("bỏ qua file test và giá trị mẫu", () => {
    const files = [{ path: "tests/a.test.js", content: 'const password = "Xk9#mP2$vL8@qR4";' }, { path: "src/c.js", content: 'const password = "your_password_here";' }];
    expect(analyzeSource({ files, allPaths: files.map((f) => f.path) }).some((i) => i.id === "hardcoded-credentials")).toBe(false);
  });
});

describe("deps", () => {
  const pkg = { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "^4.17.0" } }) };
  const lock = { path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" }, "node_modules/dev": { version: "1.0.0", dev: true } } }) };
  it("đọc lockfile, bỏ dev", () => {
    const p = parseManifests([pkg, lock]);
    expect(p.deps).toEqual([{ name: "lodash", version: "4.17.20", eco: "npm", direct: true, manifest: "package.json" }]);
    expect(p.hasLockfile).toBe(true);
  });
  it("đối chiếu OSV thật sự dựa trên phản hồi và gợi ý bản vá", async () => {
    const p = parseManifests([pkg, lock]);
    const f = (async (url: string) => String(url).includes("querybatch")
      ? respond({ results: [{ vulns: [{ id: "GHSA-1" }] }] })
      : respond({ id: "GHSA-1", summary: "Prototype pollution", aliases: ["CVE-2021-1"], database_specific: { severity: "HIGH" }, affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] })) as unknown as typeof fetch;
    const { hits, ok } = await findVulns(p.deps, f);
    const it = vulnItems(hits, p, ok)[0]!;
    expect(it).toMatchObject({ status: "fail", severity: "high" });
    expect(it.fix?.snippet?.code).toBe("npm install lodash@4.17.21");
  });
  it("OSV lỗi → unknown, không bịa kết quả", async () => {
    const p = parseManifests([pkg, lock]);
    const r = await findVulns(p.deps, (async () => respond("", 500)) as typeof fetch);
    expect(vulnItems(r.hits, p, r.ok)[0]!.status).toBe("unknown");
  });
});

describe("system scan", () => {
  const REF = "abcdefghijklmnopqrst";
  const jwt = (p: object) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify(p)).toString("base64url")}.sig`;
  it("từ chối service_role và tên miền lạ", async () => {
    await expect(scanSupabase({ url: REF, anonKey: jwt({ role: "service_role", ref: REF }) })).rejects.toMatchObject({ code: "service_role" });
    await expect(scanSupabase({ url: "http://169.254.169.254", anonKey: jwt({ role: "anon" }) })).rejects.toBeInstanceOf(SystemScanError);
    await expect(scanFirebase({ projectId: "x", })).rejects.toBeInstanceOf(SystemScanError);
  });
  it("Supabase: bảng đọc được → critical; chỉ dùng HEAD/đếm", async () => {
    const calls: string[] = [];
    const f = (async (url: string, init?: RequestInit) => {
      const u = String(url); calls.push(`${init?.method ?? "GET"} ${u}`);
      if (u.endsWith("/auth/v1/settings")) return respond({ disable_signup: false, mailer_autoconfirm: true, external: { email: true } });
      if (u.endsWith("/rest/v1/")) return respond({ paths: { "/": {}, "/orders": {}, "/notes": {} } });
      if (u.includes("/rest/v1/orders")) return new Response(null, { status: 206, headers: { "content-range": "0-0/42" } });
      if (u.includes("/rest/v1/notes")) return new Response(null, { status: 206, headers: { "content-range": "*/0" } });
      if (u.endsWith("/storage/v1/bucket")) return respond([{ name: "pics", public: true }]);
      return respond({}, 404);
    }) as unknown as typeof fetch;
    const r = await scanSupabase({ url: `https://${REF}.supabase.co`, anonKey: jwt({ role: "anon", ref: REF }) }, f);
    expect(r.items.find((i) => i.id === "sb-table-open:orders")).toMatchObject({ status: "fail", severity: "critical" });
    expect(r.items.find((i) => i.id === "sb-table-open:notes")).toBeUndefined();
    expect(r.items.find((i) => i.id === "sb-auth-autoconfirm")?.status).toBe("fail");
    expect(r.items.find((i) => i.id === "sb-bucket-public:pics")?.status).toBe("fail");
    expect(calls.every((c) => /^(GET|HEAD|OPTIONS) /.test(c) || /object\/list|graphql/.test(c))).toBe(true); // POST chỉ cho liệt kê/introspection (đọc)
    expect(JSON.stringify(r.items)).not.toContain("eyJ");
  });
  it("Firebase: RTDB mở → critical; 401 → đạt", async () => {
    const open = (async (u: string) => (String(u).includes("firebaseio") ? respond({ users: true }) : respond({}, 403))) as unknown as typeof fetch;
    expect((await scanFirebase({ projectId: "my-app-12345" }, open)).items.find((i) => i.id === "fb-rtdb-open")?.severity).toBe("critical");
    const closed = (async (u: string) => (String(u).includes("firebaseio") ? respond({ error: "Permission denied" }, 401) : respond({}, 403))) as unknown as typeof fetch;
    expect((await scanFirebase({ projectId: "my-app-12345" }, closed)).items.find((i) => i.id === "fb-rtdb-closed")?.status).toBe("pass");
  });
});

describe("launch", () => {
  const fail = (id: string, severity: "critical" | "medium", source: "code" | "system" = "code") => item({ id, group: "g", source, title: id, severity, status: "fail", summary: "s", why: "w" });
  const pass = (id: string, source: "code" | "system" = "code") => item({ id, group: "g", source, title: id, severity: "info", status: "pass", summary: "s", why: "w" });
  const src = (items: ReturnType<typeof item>[]) => ({ id: "x", label: "o/r", createdAt: "2026-01-01T00:00:00Z", items });
  it("kết luận đúng 3 mức", () => {
    expect(evaluateLaunch({ website: null, code: src([fail("a", "critical")]), system: null, skipped: ["system"] }).verdict).toBe("not_ready");
    expect(evaluateLaunch({ website: null, code: src([fail("a", "medium")]), system: null, skipped: ["system"] }).verdict).toBe("fix_first");
    expect(evaluateLaunch({ website: null, code: src([pass("a")]), system: src([pass("b", "system")]), skipped: [] }).verdict).toBe("fix_first"); // chưa quét website
  });
  it("Before/After: đã sửa, còn lại, mới, chưa quét lại", () => {
    const before = evaluateLaunch({ website: null, code: src([fail("a", "critical"), fail("b", "medium")]), system: src([fail("s1", "critical", "system")]), skipped: [] });
    const after = evaluateLaunch({ website: null, code: src([pass("a"), fail("b", "medium"), fail("c", "medium")]), system: null, skipped: ["system"] });
    const d = compareLaunch({ items: before.items, createdAt: "t", verdict: before.verdict, score: before.score.score }, after);
    expect(d.resolved.map((i) => i.id)).toEqual(["a"]);
    expect(d.remaining.map((i) => i.id)).toEqual(["b"]);
    expect(d.added.map((i) => i.id)).toEqual(["c"]);
    expect(d.notRechecked.map((i) => i.id)).toEqual(["s1"]);
  });
});

describe("project-repo", () => {
  it("chỉ chủ sở hữu đọc được", async () => {
    const db = createTestD1();
    const a = await seedUser(db, "a@x.com"), b = await seedUser(db, "b@x.com");
    const items = [pass("p")];
    const id = await insertProjectScan(db, { userId: a, kind: "code", label: "o/r", score: scoreItems(items).score, grade: "A", counts: {}, items, retentionDays: 30 });
    expect((await getProjectScan(db, a, id))?.items).toHaveLength(1);
    expect(await getProjectScan(db, b, id)).toBeNull();
    expect((await latestByLabel(db, a, "code", "o/r"))?.id).toBe(id);
  });
});
function pass(id: string) { return item({ id, group: "g", source: "code", title: id, severity: "info", status: "pass", summary: "s", why: "w" }); }
