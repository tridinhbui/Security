import { readFileSync } from "node:fs";
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTestD1 } from "@/lib/db/__tests__/test-d1";

/**
 * Kiểm thử bảo mật của API bình chọn “Giải thích này có rõ không?” — chạy trên D1 THẬT (SQLite) trong bộ nhớ, KHÔNG chạm production.
 * (Không thể kiểm thử giới hạn tốc độ hay chống trùng trên production mà không tạo phiếu giả, nên làm ở đây.)
 */
const state = vi.hoisted(() => ({ db: null as unknown, user: null as null | { id: string } }));
vi.mock("@/lib/cf", () => ({ getDb: async () => state.db }));
vi.mock("@/lib/auth/next", () => ({ getUser: async () => state.user }));

import { POST } from "@/app/api/explain-feedback/route";

type Db = ReturnType<typeof createTestD1>;
const HOST = "app.test";
function req(body: unknown, o: { origin?: string | null; ip?: string } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json", host: HOST, "cf-connecting-ip": o.ip ?? "203.0.113.7" };
  if (o.origin !== null) headers.origin = o.origin ?? `https://${HOST}`;
  return new NextRequest(`https://${HOST}/api/explain-feedback`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
}
const good = { ruleId: "headers.csp", variant: "", verdict: "clear", source: "quick", mode: "beginner" };
const rows = () => (state.db as Db).sqlite.prepare("SELECT * FROM explain_feedback ORDER BY created_at").all() as Record<string, unknown>[];

beforeEach(() => { process.env.IP_HASH_SECRET = "test-secret-0123456789"; state.db = createTestD1(); state.user = null; });

describe("POST /api/explain-feedback — CSRF và xác thực đầu vào", () => {
  it("từ chối khi thiếu Origin hoặc Origin khác host (403) và không ghi gì", async () => {
    expect((await POST(req(good, { origin: null }))).status).toBe(403);
    expect((await POST(req(good, { origin: "https://evil.example" }))).status).toBe(403);
    expect((await POST(req(good, { origin: "https://app.test.evil.example" }))).status).toBe(403);
    expect(rows()).toHaveLength(0);
  });
  it.each([
    ["JSON hỏng", "{not json"],
    ["luật không tồn tại", { ...good, ruleId: "khong.ton.tai" }],
    ["thiếu ruleId", { verdict: "clear", source: "quick" }],
    ["verdict lạ", { ...good, verdict: "maybe" }],
    ["thiếu source", { ruleId: "headers.csp", verdict: "clear" }],
    ["source lạ", { ...good, source: "admin" }],
    ["ruleId kiểu SQL", { ...good, ruleId: "x'; DROP TABLE explain_feedback;--" }],
  ])("400 với %s và không ghi gì", async (_n, body) => {
    expect((await POST(req(body))).status).toBe(400);
    expect(rows()).toHaveLength(0);
  });
  it("201 với phiếu hợp lệ, phản hồi không lưu cache", async () => {
    const res = await POST(req(good));
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(rows()).toHaveLength(1);
  });
});

describe("dữ liệu riêng tư", () => {
  it("không lưu IP thô, tên miền hay URL ở bất kỳ cột nào; biến thể chứa tên miền bị bỏ", async () => {
    await POST(req({ ...good, ruleId: "browser.form-targets", variant: "x:khach-hang-bi-mat.example.net", comment: "" }, { ip: "198.51.100.23" }));
    await POST(req({ ...good, ruleId: "headers.broken", variant: "https://khach-hang-bi-mat.example.net/login" }, { ip: "198.51.100.23" }));
    const all = JSON.stringify(rows());
    for (const secret of ["198.51.100.23", "khach-hang-bi-mat", "example.net", "https://"]) expect(all).not.toContain(secret);
    for (const r of rows()) { expect(r.variant).toBe(""); expect(String(r.voter_hash)).toMatch(/^[0-9a-f]{32}$/); }
  });
  it("giữ biến thể an toàn (vd xfo) và chỉ lưu nhận xét khi chọn “chưa rõ”, đã cắt 300 ký tự", async () => {
    await POST(req({ ...good, ruleId: "headers.broken", variant: "xfo", verdict: "clear", comment: "không nên được lưu" }, { ip: "1.1.1.1" }));
    await POST(req({ ...good, ruleId: "headers.broken", variant: "referrer", verdict: "unclear", comment: "chỗ này khó hiểu ".repeat(60) }, { ip: "1.1.1.1" }));
    const r = rows();
    expect(r.find((x) => x.variant === "xfo")).toMatchObject({ verdict: "clear", comment: "" });
    expect(String(r.find((x) => x.variant === "referrer")!.comment)).toHaveLength(300);
  });
  it("nhận xét tự do: tên miền, email, IP, URL, token, số điện thoại bị ẩn TRƯỚC khi lưu", async () => {
    const dirty = "web khachhang-bi-mat.com bị lỗi, liên hệ nguyen.van@congty.vn hoặc 0912 345 678, server 203.0.113.99, xem https://khachhang-bi-mat.com/admin?k=1 token sk_live_ABCDEF1234567890abcdef";
    await POST(req({ ...good, verdict: "unclear", comment: dirty }));
    const c = String(rows()[0]!.comment);
    for (const leak of ["khachhang-bi-mat", "congty.vn", "nguyen.van", "0912", "203.0.113.99", "sk_live", "https://"]) expect(c, `lộ ${leak}`).not.toContain(leak);
    expect(c).toContain("[đã ẩn]");
    expect(c).toMatch(/bị lỗi/); // phần văn bản vô hại vẫn giữ
  });
  it("chế độ lạ bị đổi về mặc định; không có cột nào chứa cookie, User-Agent hay email", async () => {
    await POST(req({ ...good, mode: "<script>alert(1)</script>" }));
    expect(rows()[0]!.mode).toBe("beginner");
    expect(Object.keys(rows()[0]!).sort()).toEqual(["comment", "created_at", "id", "mode", "rule_id", "source", "updated_at", "variant", "verdict", "voter_hash"]);
  });
});

describe("chống bình chọn trùng và lạm dụng", () => {
  it("cùng một người bình chọn lại là ĐỔI phiếu (không nhân đôi); người khác tính riêng", async () => {
    await POST(req({ ...good, verdict: "clear" }, { ip: "10.9.9.1" }));
    await POST(req({ ...good, verdict: "unclear", comment: "đổi ý" }, { ip: "10.9.9.1" }));
    expect(rows()).toHaveLength(1);
    expect(rows()[0]).toMatchObject({ verdict: "unclear", comment: "đổi ý" });
    await POST(req({ ...good, verdict: "clear" }, { ip: "10.9.9.2" }));
    expect(rows()).toHaveLength(2);
  });
  it("người đã đăng nhập tính theo tài khoản, không theo IP: đổi IP không bơm thêm phiếu", async () => {
    state.user = { id: "u-1" };
    await POST(req(good, { ip: "10.1.1.1" }));
    await POST(req(good, { ip: "10.2.2.2" }));
    await POST(req(good, { ip: "10.3.3.3" }));
    expect(rows()).toHaveLength(1);
    state.user = null;
    await POST(req(good, { ip: "10.1.1.1" })); // cùng IP nhưng ẩn danh: voter khác với tài khoản
    expect(rows()).toHaveLength(2);
  });
  it("giới hạn 60 phiếu/giờ/người → 429; người khác không bị ảnh hưởng", async () => {
    const ids = ["headers.csp", "headers.broken", "tls.hsts", "cookies.flags", "browser.cors", "privacy.referrer-policy"];
    let sent = 0;
    for (const id of ids) for (let i = 0; i < 10 && sent < 60; i++, sent++) expect((await POST(req({ ...good, ruleId: id, variant: `v${i}` }, { ip: "172.16.0.9" }))).status).toBe(201);
    const over = await POST(req({ ...good, ruleId: "headers.csp", variant: "vuot" }, { ip: "172.16.0.9" }));
    expect(over.status).toBe(429);
    expect((await POST(req({ ...good, variant: "vuot" }, { ip: "172.16.0.10" }))).status).toBe(201);
  });
  it("Hạn chế đã biết (ghi nhận, không phải lỗi): nhiều người sau cùng một IP công cộng dùng chung một phiếu", async () => {
    await POST(req({ ...good, verdict: "clear" }, { ip: "192.0.2.50" }));
    await POST(req({ ...good, verdict: "unclear" }, { ip: "192.0.2.50" }));
    expect(rows()).toHaveLength(1);
  });
});

describe("quyền admin của trang tổng hợp", () => {
  it("mọi trang admin kiểm tra quyền (getAdmin → notFound) TRƯỚC khi chạm cơ sở dữ liệu", () => {
    for (const p of ["src/app/(app)/admin/giai-thich/page.tsx", "src/app/(app)/admin/page.tsx"]) {
      const src = readFileSync(p, "utf8");
      const gate = src.search(/if \(!\(await getAdmin\(\)\)\) notFound\(\)/);
      const db = src.search(/getDb\(\)/);
      expect(gate, `${p} thiếu cổng admin`).toBeGreaterThan(-1);
      expect(gate, `${p}: cổng admin phải đứng trước getDb`).toBeLessThan(db);
    }
  });
});

describe("tăng cường (Phase 3.2 release-ready)", () => {
  it("413 khi nội dung thật vượt 4 KB dù không có content-length", async () => {
    const big = JSON.stringify({ ...good, comment: "a b ".repeat(2000) });
    const r = new NextRequest(`https://${HOST}/api/explain-feedback`, { method: "POST", headers: { host: HOST, origin: `https://${HOST}`, "cf-connecting-ip": "203.0.113.9" }, body: big });
    r.headers.delete("content-length");
    expect((await POST(r)).status).toBe(413);
    expect(rows()).toHaveLength(0);
  });
  it("body là mảng/null/chuỗi JSON → 400", async () => {
    for (const b of ["[]", "null", '"x"', "123"]) expect((await POST(req(b))).status).toBe(400);
  });
  it("IPv6 cùng /64 được tính là một người (không tách phiếu bằng cách đổi 64 bit cuối)", async () => {
    await POST(req(good, { ip: "2001:db8:1:2::1" }));
    await POST(req({ ...good, verdict: "unclear" }, { ip: "2001:db8:1:2:aaaa:bbbb:cccc:dddd" }));
    expect(rows()).toHaveLength(1);
    await POST(req(good, { ip: "2001:db8:1:3::1" })); // /64 khác → người khác
    expect(rows()).toHaveLength(2);
  });
  it("IPv4 nhúng trong IPv6 (::ffff:a.b.c.d) vẫn là từng máy riêng, không bị gom chung", async () => {
    await POST(req(good, { ip: "::ffff:198.51.100.1" }));
    await POST(req(good, { ip: "::ffff:198.51.100.2" }));
    expect(rows()).toHaveLength(2);
    await POST(req({ ...good, verdict: "unclear" }, { ip: "198.51.100.1" })); // cùng máy ở dạng IPv4 thuần
    expect(rows()).toHaveLength(2);
  });
  it("voterNet: các dạng viết khác nhau của cùng một /64 giống nhau; /64 khác nhau thì khác", async () => {
    const { voterNet } = await import("@/lib/http/guards");
    expect(voterNet("2001:DB8:0:0::1")).toBe(voterNet("2001:db8::ffff"));
    expect(voterNet("fe80::1%eth0")).toBe(voterNet("fe80::2"));
    expect(voterNet("2001:db8:1:2::1")).not.toBe(voterNet("2001:db8:1:3::1"));
    expect(voterNet("203.0.113.5")).toBe("203.0.113.5");
    expect(voterNet(null)).toBe("unknown");
  });
});
