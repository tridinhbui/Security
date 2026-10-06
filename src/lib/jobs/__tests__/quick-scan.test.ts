import { beforeEach, describe, expect, it } from "vitest";
import { createTestD1 } from "@/lib/db/__tests__/test-d1";
import { QUICK_RULES } from "@/lib/scanner/quick";
import type { Resolver } from "@/lib/ssrf/dns";
import { quickLimits, quickScan, type QuickLimits } from "../quick-scan";

const resolver: Resolver = async () => [{ address: "93.184.216.34", family: 4 }];
const PAGE = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Trang</title>
<script src="https://cdn.jsdelivr.net/npm/lib@1/lib.js"></script></head><body><img src="http://img.other.net/a.png"><a href="/x">x</a></body></html>`;
const HEADERS = { "content-type": "text/html; charset=utf-8", server: "nginx/1.18.0", "set-cookie": "sid=abc; Path=/" };

function setup(over: { https?: () => Response; limits?: Partial<QuickLimits> } = {}) {
  const db = createTestD1();
  const fetched: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) return new Response(JSON.stringify({ Status: 0, Answer: [] }));
    fetched.push(`${init?.method ?? "GET"} ${url}`);
    if (url === "http://site.com/") return new Response(null, { status: 301, headers: { location: "https://site.com/" } });
    if (url === "https://site.com/") return over.https ? over.https() : new Response(PAGE, { headers: HEADERS });
    return new Response("nope", { status: 404 });
  }) as typeof fetch;
  const run = (url: string, ip = "ip1", limits?: Partial<QuickLimits>) => quickScan(db, { url, ipHash: ip, resolver, fetchImpl, limits: { ...quickLimits(), ...over.limits, ...limits } });
  return { db, fetched, run };
}

describe("quickScan — chạy thật, không dữ liệu giả", () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => { t = setup(); });

  it("trả điểm 0–100 và các mục Đạt / Cảnh báo / Lỗi dựa trên phản hồi thật", async () => {
    const out = await t.run("site.com");
    if (!out.ok) throw new Error(out.message);
    const r = out.result;
    expect(r.host).toBe("site.com");
    expect(r.score).toBeGreaterThanOrEqual(0); expect(r.score).toBeLessThanOrEqual(90); // quét nhanh: trần 90
    expect(r.counts.fail + r.counts.warning + r.counts.pass).toBe(r.items.length);
    const byGroup = (g: string, s?: string) => r.items.filter((i) => i.label.includes(g) && (!s || i.status === s));
    expect(byGroup("Cookie", "fail").length + byGroup("Cookie", "warning").length).toBeGreaterThan(0); // cookie sid thiếu cờ
    expect(r.items.some((i) => i.label.startsWith("Nội dung hỗn hợp") && i.status !== "pass")).toBe(true); // ảnh http://
    expect(r.items.some((i) => i.label.startsWith("Script bên ngoài") && i.status !== "pass")).toBe(true); // script CDN thiếu SRI
    expect(r.items.some((i) => i.label === "CSP" && i.status === "fail")).toBe(true); // thiếu CSP
    expect(r.items.some((i) => i.label === "Header bảo mật" && i.status !== "pass")).toBe(true);
    expect(r.items.some((i) => i.label === "HTTPS / SSL" && i.status === "pass")).toBe(true);
    expect(r.items.every((i) => i.text.length > 0 && i.text.length <= 171)).toBe(true);
    // lỗi xếp trước, đạt xếp sau
    const ranks = r.items.map((i) => ({ fail: 0, warning: 1, pass: 2 }[i.status]));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it("chỉ chạy tập luật nhanh, chỉ trang gốc, ít request, không tải script ngoài, không OPTIONS", async () => {
    const out = await t.run("site.com/some/deep/path?token=SECRET#x");
    expect(out.ok).toBe(true);
    expect(t.fetched.length).toBeLessThanOrEqual(14);
    expect(t.fetched.every((f) => !f.includes("SECRET") && !f.includes("/some/deep"))).toBe(true);
    expect(t.fetched.some((f) => f.includes("cdn.jsdelivr.net"))).toBe(false);
    expect(t.fetched.some((f) => f.startsWith("OPTIONS"))).toBe(false);
    if (out.ok) for (const i of out.result.items) expect(Object.keys(QUICK_RULES).some((id) => i.id.startsWith(`${id}|`))).toBe(true);
  });

  it("bộ nhớ đệm theo tên miền: lần hai không gửi request nào và không tính hạn mức quét thật", async () => {
    await t.run("site.com");
    const n = t.fetched.length;
    const again = await t.run("https://site.com/other/page");
    expect(again).toMatchObject({ ok: true, cached: true });
    expect(t.fetched.length).toBe(n);
    const fresh = (t.db.sqlite.prepare("SELECT COUNT(*) c FROM quick_scan_log WHERE cached=0").get() as { c: number }).c;
    expect(fresh).toBe(1);
  });

  it("website không tới được → điểm 0, không bịa kết quả", async () => {
    const down = setup({ https: () => { throw new TypeError("net"); } });
    const out = await down.run("site.com");
    if (!out.ok) throw new Error(out.message);
    expect(out.result.score).toBe(0);
    expect(out.result.items[0]).toMatchObject({ status: "fail" });
  });

  it("chặn SSRF: IP nội bộ, localhost, metadata, cổng lạ — không gửi request nào", async () => {
    for (const u of ["http://127.0.0.1/", "http://169.254.169.254/latest", "localhost", "http://10.0.0.5:8080/", "ftp://site.com", "https://user:pw@site.com"]) {
      const out = await t.run(u);
      expect(out, u).toMatchObject({ ok: false, status: 400 });
    }
    expect(t.fetched).toEqual([]);
  });

  it("không tự quét chính hệ thống", async () => {
    const calls: string[] = [];
    const out = await quickScan(t.db, { url: "site.com", ipHash: "x", resolver, denyHosts: ["site.com"], fetchImpl: (async (u: RequestInfo | URL) => { calls.push(String(u)); return new Response(""); }) as typeof fetch });
    expect(out).toMatchObject({ ok: false, status: 400, code: "internal_hostname" });
    expect(calls.filter((c) => !c.startsWith("https://cloudflare-dns.com/"))).toEqual([]);
  });

  it("giới hạn theo IP: quét thật vượt hạn mức → 429; IP khác không bị ảnh hưởng", async () => {
    const s = setup({ limits: { freshPerHour: 2, hostPerHour: 99 } });
    expect((await s.run("a.com", "ipA")).ok).toBe(true);
    expect((await s.run("b.com", "ipA")).ok).toBe(true);
    expect(await s.run("c.com", "ipA")).toMatchObject({ ok: false, status: 429 });
    expect((await s.run("c.com", "ipB")).ok).toBe(true);
  });

  it("giới hạn theo tên miền và toàn hệ thống; lượt trúng đệm vẫn bị chặn nếu gọi dồn dập", async () => {
    const s = setup({ limits: { hostPerHour: 1, freshPerHour: 99, freshPerDay: 99 } });
    s.db.sqlite.prepare("INSERT INTO quick_scan_log (ip_hash,host,cached,at) VALUES ('z','site.com',0,?)").run(new Date().toISOString());
    expect(await s.run("site.com", "ipC")).toMatchObject({ ok: false, status: 429 });
    const g = setup({ limits: { globalPerDay: 1, hostPerHour: 99, freshPerHour: 99, freshPerDay: 99 } });
    expect((await g.run("a.com", "i1")).ok).toBe(true);
    expect(await g.run("b.com", "i2")).toMatchObject({ ok: false, status: 429 });
    const any = setup({ limits: { anyPerHour: 2 } });
    await any.run("site.com", "ipD"); await any.run("site.com", "ipD");
    expect(await any.run("site.com", "ipD")).toMatchObject({ ok: false, status: 429 });
  });

  it("đầu vào rỗng/quá dài → 400; IP chỉ lưu dạng băm do bên gọi truyền vào", async () => {
    expect(await t.run("")).toMatchObject({ ok: false, status: 400 });
    expect(await t.run("a".repeat(3000))).toMatchObject({ ok: false, status: 400 });
  });
});
