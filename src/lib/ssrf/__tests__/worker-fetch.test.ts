import { describe, expect, it } from "vitest";
import { ScanBudget } from "../budget";
import type { Resolver } from "../dns";
import { createWorkerFetcher } from "../worker-fetch";

const PUBLIC: Resolver = async (h) => (h === "privhost.com" ? [{ address: "10.0.0.5", family: 4 }] : h === "mixedhost.com" ? [{ address: "93.184.216.34", family: 4 }, { address: "192.168.1.1", family: 4 }] : [{ address: "93.184.216.34", family: 4 }]);

function make(routes: Record<string, () => Response>, opts: { deny?: string[]; budget?: ScanBudget } = {}) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const r = routes[url];
    if (!r) throw new TypeError("network");
    return r();
  }) as unknown as typeof fetch;
  const budget = opts.budget ?? new ScanBudget(10, 1_000_000, 30_000);
  return { calls, fetch: createWorkerFetcher(budget, { resolver: PUBLIC, fetchImpl, denyHosts: opts.deny }), budget };
}
const html = (body: string, headers: Record<string, string> = {}) => () => new Response(body, { headers: { "content-type": "text/html", ...headers } });
const redirect = (to: string) => () => new Response(null, { status: 302, headers: { location: to } });

describe("worker fetcher — chống SSRF", () => {
  it("lấy trang bình thường, giữ header và nhiều Set-Cookie", async () => {
    const h = new Headers({ "content-type": "text/html" }); h.append("set-cookie", "a=1; Secure"); h.append("set-cookie", "b=2; HttpOnly");
    const { fetch, calls } = make({ "https://example.com/": () => new Response("<h1>hi</h1>", { headers: h }) });
    const r = await fetch("https://example.com/");
    expect(r).toMatchObject({ status: 200, body: "<h1>hi</h1>", contentType: "text/html", resolved: ["93.184.216.34"] });
    expect(r.headers["set-cookie"]).toEqual(["a=1; Secure", "b=2; HttpOnly"]);
    expect(calls[0]!.init).toMatchObject({ redirect: "manual", method: "GET" });
    expect((calls[0]!.init!.headers as Record<string, string>)["accept-encoding"]).toBe("identity");
  });
  it.each([
    ["http://127.0.0.1/", "non_public_ip"], ["http://169.254.169.254/latest/meta-data", "non_public_ip"], ["http://[::1]/", "non_public_ip"],
    ["http://localhost/", "internal_hostname"], ["https://svc.internal/", "internal_hostname"], ["ftp://example.com/", "scheme_not_allowed"],
    ["https://u:p@example.com/", "credentials_not_allowed"], ["https://example.com:22/", "port_not_allowed"],
    ["https://privhost.com/", "non_public_ip"], ["https://mixedhost.com/", "dns_mixed_answers"],
  ])("từ chối %s (%s) và không gọi fetch", async (url, code) => {
    const { fetch, calls } = make({});
    const r = await fetch(url);
    expect(r.error).toMatchObject({ code, blocked: true });
    expect(calls).toHaveLength(0);
  });
  it("kiểm tra lại MỖI bước chuyển hướng: không bị dẫn sang IP nội bộ", async () => {
    const { fetch, calls } = make({ "https://example.com/": redirect("http://169.254.169.254/latest/"), "http://169.254.169.254/latest/": html("SECRET") });
    const r = await fetch("https://example.com/");
    expect(r.error).toMatchObject({ code: "non_public_ip", blocked: true });
    expect(calls.map((c) => c.url)).toEqual(["https://example.com/"]);
  });
  it("chuyển hướng sang tên miền trỏ vào IP riêng bị chặn", async () => {
    const { fetch } = make({ "https://example.com/": redirect("https://privhost.com/x") });
    expect((await fetch("https://example.com/")).error).toMatchObject({ code: "non_public_ip", blocked: true });
  });
  it("theo chuyển hướng hợp lệ, phát hiện vòng lặp và giới hạn số lần", async () => {
    const ok = make({ "http://example.com/": redirect("https://example.com/"), "https://example.com/": html("done") });
    const r = await ok.fetch("http://example.com/");
    expect(r).toMatchObject({ status: 200, finalUrl: "https://example.com/", body: "done" });
    expect(r.chain.map((c) => c.status)).toEqual([302, 200]);
    const loop = make({ "https://example.com/": redirect("https://example.com/") });
    expect((await loop.fetch("https://example.com/")).error?.code).toBe("redirect_loop");
  });
  it("followRedirects=false trả về chính phản hồi 3xx", async () => {
    const { fetch } = make({ "https://example.com/": redirect("https://example.com/b") });
    expect(await fetch("https://example.com/", { followRedirects: false })).toMatchObject({ status: 302, headers: { location: "https://example.com/b" } });
  });
  it("giới hạn dung lượng thân phản hồi và tính vào ngân sách byte", async () => {
    const { fetch, budget } = make({ "https://example.com/": html("x".repeat(5000)) });
    const r = await fetch("https://example.com/", { maxBytes: 100 });
    expect(r.body).toHaveLength(100);
    expect(r.truncated).toBe(true);
    expect(budget.bytes).toBe(100);
  });
  it("ngân sách request: vượt thì dừng", async () => {
    const { fetch } = make({ "https://example.com/": html("a") }, { budget: new ScanBudget(1, 1_000_000, 30_000) });
    expect((await fetch("https://example.com/")).status).toBe(200);
    expect((await fetch("https://example.com/")).error?.code).toBe("request_budget");
  });
  it("lỗi mạng/chứng chỉ → error (không ném), để bên gọi chuyển sang đường container", async () => {
    const { fetch } = make({});
    expect((await fetch("https://example.com/")).error?.code).toBe("FETCH_FAILED");
  });
  it("không tự quét chính hệ thống", async () => {
    const { fetch, calls } = make({}, { deny: ["security.example.workers.dev"] });
    expect((await fetch("https://security.example.workers.dev/")).error).toMatchObject({ code: "internal_hostname", blocked: true });
    expect((await fetch("https://a.security.example.workers.dev/")).error?.blocked).toBe(true);
    expect(calls).toHaveLength(0);
  });
});
