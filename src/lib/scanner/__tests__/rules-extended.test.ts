import { describe, expect, it } from "vitest";
import { EFFORT, buildRoadmap, buildSummary, effortFor, toMarkdown } from "@/lib/guidance";
import { PLAIN_TITLES } from "@/lib/beginner";
import { CATEGORY_LABEL, SEV_LABEL } from "@/lib/i18n";
import { alternateHost } from "../collect";
import { ALL_RULES } from "../rules";
import { spfLookupCount } from "../rules/config";
import { detectLibraries } from "../rules/exposure";
import { detectTrackers } from "../rules/privacy";
import { calculateScore } from "../score";
import { CATEGORIES } from "../types";
import { baseline, failing, GOOD_HEADERS, hdr, rec, run, setHtml } from "./fixtures";

const keys = (fs: { fingerprint: string }[]) => fs.map((f) => f.fingerprint.split("|")[1]);

// ---------------------------------------------------------------- TLS mới
describe("tls.certificate-strength", () => {
  const id = "tls.certificate-strength";
  it("RSA dưới 2048 bit → Medium; EC quá ngắn → Medium", () => {
    const o = baseline(); Object.assign(o.https!.tls!, { keyType: "rsa", keyBits: 1024 });
    expect(failing(o, id)[0]).toMatchObject({ severity: "medium", confidence: "high" });
    Object.assign(o.https!.tls!, { keyType: "ec", keyBits: 160 });
    expect(failing(o, id)).toHaveLength(1);
  });
  it("EC 256 bit và RSA 2048 bit đều đạt", () => {
    const o = baseline(); Object.assign(o.https!.tls!, { keyType: "ec", keyBits: 256, curve: "prime256v1" });
    expect(run(o, id)[0]!.status).toBe("pass");
    expect(run(baseline(), id)[0]!.status).toBe("pass");
  });
  it("thời hạn > 398 ngày → Low (độ tin cậy vừa)", () => {
    const o = baseline(); o.https!.tls!.validityDays = 825;
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "medium" });
  });
  it("wildcard chỉ là ghi chú, không trừ điểm", () => {
    const o = baseline(); Object.assign(o.https!.tls!, { wildcard: true, altNames: ["*.example.com", "example.com"] });
    const f = run(o, id).find((x) => x.fingerprint.endsWith("|wildcard"))!;
    expect(f).toMatchObject({ status: "info", severity: "info" });
    expect(failing(o, id)).toHaveLength(0);
  });
  it("im lặng khi không có thông tin khoá hoặc chứng chỉ lỗi", () => {
    const o = baseline(); delete o.https!.tls!.keyType;
    expect(run(o, id)).toHaveLength(0);
    const p = baseline(); p.https!.certError = { code: "CERT_HAS_EXPIRED", message: "x" };
    expect(run(p, id)).toHaveLength(0);
  });
});

describe("tls.http2", () => {
  const id = "tls.http2";
  it("h2 → đạt; chỉ http/1.1 → ghi chú (không trừ điểm)", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); o.legacyTls = { tls10: false, tls11: false, h2: false };
    expect(run(o, id)[0]).toMatchObject({ status: "info", severity: "info" });
  });
  it("im lặng nếu không probe được", () => {
    const o = baseline(); o.legacyTls = { tls10: false, tls11: false, h2: null };
    expect(run(o, id)).toHaveLength(0);
    o.legacyTls = null;
    expect(run(o, id)).toHaveLength(0);
  });
  it("gợi ý Nginx chỉ khi nhận diện được Nginx", () => {
    const o = baseline(); o.legacyTls = { tls10: false, tls11: false, h2: false }; o.platforms = ["nginx"];
    expect(run(o, id)[0]!.remediation!.steps!.join()).toContain("http2");
  });
});

describe("tls.www-consistency", () => {
  const id = "tls.www-consistency";
  it("chứng chỉ lỗi ở phiên bản còn lại → Low", () => {
    const o = baseline(); o.altHost = { host: "www.example.com", record: rec({ status: 200, certError: { code: "ERR_TLS_CERT_ALTNAME_INVALID", message: "x" } }) };
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "high" });
  });
  it("không phản hồi → ghi chú; bị chặn hoặc DNS không có → im lặng", () => {
    const o = baseline(); o.altHost = { host: "www.example.com", record: rec({ status: null, error: { code: "ECONNREFUSED", message: "x" } }) };
    expect(run(o, id)[0]).toMatchObject({ status: "info" });
    o.altHost = { host: "www.example.com", record: rec({ status: null, error: { code: "non_public_ip", message: "x", blocked: true } }) };
    expect(run(o, id)).toHaveLength(0);
    o.altHost = { host: "www.example.com", record: null };
    expect(run(o, id)).toHaveLength(0);
    o.altHost = null;
    expect(run(o, id)).toHaveLength(0);
  });
  it("hợp lệ → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
  it("alternateHost", () => {
    expect(alternateHost("example.com")).toBe("www.example.com");
    expect(alternateHost("www.example.com")).toBe("example.com");
    expect(alternateHost("shop.example.com")).toBeNull();
    expect(alternateHost("93.184.216.34")).toBeNull();
    expect(alternateHost("example.co.uk")).toBe("www.example.co.uk");
  });
});

// ---------------------------------------------------------------- Header mới
describe("headers.cross-origin-isolation", () => {
  const id = "headers.cross-origin-isolation";
  it("thiếu → ghi chú; đủ ba header → đạt; không bao giờ là lỗi", () => {
    const o = baseline();
    expect(run(o, id)[0]).toMatchObject({ status: "info", severity: "info" });
    Object.assign(hdr(o), { "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin", "cross-origin-embedder-policy": "require-corp" });
    expect(run(o, id)[0]!.status).toBe("pass");
    expect(failing(baseline(), id)).toHaveLength(0);
  });
});

describe("headers.charset", () => {
  const id = "headers.charset";
  it("không khai báo ở cả header lẫn meta → Low (độ tin cậy vừa)", () => {
    const o = baseline(); o.https!.contentType = "text/html"; hdr(o)["content-type"] = "text/html"; setHtml(o, "<html><body>x</body></html>");
    expect(failing(o, id)[0]).toMatchObject({ severity: "low", confidence: "medium" });
  });
  it("đạt khi có trong header hoặc trong meta", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); o.https!.contentType = "text/html"; setHtml(o, '<meta charset="utf-8">');
    expect(run(o, id)[0]!.status).toBe("pass");
  });
});

describe("headers.csp — kiểm tra sâu hơn", () => {
  const id = "headers.csp";
  const withCsp = (v: string) => { const o = baseline(); hdr(o)["content-security-policy"] = v; return o; };
  it("data:/blob: trong script-src → Medium", () => {
    expect(failing(withCsp("default-src 'self'; script-src 'self' data:; object-src 'none'; base-uri 'self'"), id)[0]).toMatchObject({ severity: "medium" });
    expect(failing(withCsp("default-src 'self'; script-src 'self' blob:; object-src 'none'; base-uri 'self'"), id)).toHaveLength(1);
  });
  it("tin cậy CDN công cộng dễ bị lợi dụng để vượt CSP → Low", () => {
    const f = failing(withCsp("default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://ajax.googleapis.com; object-src 'none'; base-uri 'self'"), id)[0]!;
    expect(f).toMatchObject({ severity: "low" });
    expect(f.summary).toContain("cdnjs.cloudflare.com");
  });
  it("strict-dynamic bỏ qua cảnh báo host công cộng", () => {
    expect(failing(withCsp("script-src 'nonce-abc' 'strict-dynamic' https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'self'"), id)).toHaveLength(0);
  });
  it("trang có form mà thiếu form-action chỉ là gợi ý (vẫn đạt)", () => {
    const o = withCsp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
    setHtml(o, '<form method="post" action="/x"><input></form>');
    const f = run(o, id)[0]!;
    expect(f.status).toBe("pass");
    expect(f.evidence.join()).toContain("form-action");
  });
});

// ---------------------------------------------------------------- Cookie
describe("cookies.flags — thời hạn cookie phiên", () => {
  const id = "cookies.flags";
  const withCookie = (c: string) => { const o = baseline(); hdr(o)["set-cookie"] = c; o.https!.chain[0]!.headers = hdr(o); return o; };
  it("cookie phiên đủ cờ nhưng sống 1 năm → Low", () => {
    const f = failing(withCookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000"), id)[0]!;
    expect(f).toMatchObject({ severity: "low" });
    expect(f.summary).toContain("365 ngày");
  });
  it("đọc cả Expires", () => {
    const exp = new Date(Date.now() + 200 * 86_400_000).toUTCString();
    expect(failing(withCookie(`session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Expires=${exp}`), id)).toHaveLength(1);
  });
  it("thời hạn ngắn hoặc cookie không phải phiên thì không bị coi là vấn đề", () => {
    expect(failing(withCookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600"), id)).toHaveLength(0);
    expect(failing(withCookie("theme=dark; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000"), id)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------- Thư viện lỗi thời
describe("exposure.outdated-libraries", () => {
  const id = "exposure.outdated-libraries";
  const withScripts = (...urls: string[]) => { const o = baseline(); setHtml(o, urls.map((u) => `<script src="${u}"></script>`).join("")); return o; };
  it.each([
    ["https://code.jquery.com/jquery-3.4.1.min.js", "medium"],
    ["https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js", "medium"],
    ["https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js", "medium"],
    ["https://stackpath.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js", "medium"],
    ["https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.bundle.min.js", "medium"],
    ["https://ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js", "medium"],
    ["https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js", "low"],
    ["https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js", "low"],
    ["https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js", "low"],
    ["https://code.jquery.com/ui/jquery-ui-1.12.1.min.js", "medium"],
    ["https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js", "medium"],
    ["https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.9/angular.min.js", "medium"],
    ["https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js", "low"],
    ["https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js", "medium"],
  ])("%s → %s", (url, sev) => {
    const f = failing(withScripts(url), id);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: sev, confidence: "medium", status: "fail" });
  });
  it.each([
    "https://code.jquery.com/jquery-3.7.1.min.js", "https://code.jquery.com/jquery-3.5.0.min.js", "https://code.jquery.com/jquery-3.10.0.min.js",
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js", "https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js",
    "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js", "https://cdn.jsdelivr.net/npm/vue@3.4.0/dist/vue.global.js",
  ])("phiên bản an toàn %s không bị báo", (url) => {
    const r = run(withScripts(url), id);
    expect(r.every((f) => f.status === "pass")).toBe(true);
  });
  it("so sánh phiên bản theo số, không theo chuỗi (3.10.0 > 3.5.0)", () => {
    expect(detectLibraries(withScripts("https://x/jquery-3.10.0.min.js"))[0]!.severity).toBeNull();
    expect(detectLibraries(withScripts("https://x/jquery-3.4.1.min.js"))[0]!.severity).toBe("medium");
  });
  it("jQuery UI không bị nhầm thành jQuery", () => {
    const libs = detectLibraries(withScripts("https://x/jquery-ui-1.13.2.min.js"));
    expect(libs.map((l) => l.name)).toEqual(["jQuery UI"]);
    expect(libs[0]!.severity).toBeNull();
  });
  it("đọc phiên bản từ dòng chú thích đầu file khi URL không có số", () => {
    const o = baseline();
    o.html!.scripts = [{ url: "https://example.com/vendor.js", inline: false, sameOrigin: true, content: "/*! jQuery v1.11.3 | (c) jQuery Foundation */" }];
    expect(failing(o, id)[0]!.summary).toContain("jQuery 1.11.3");
  });
  it("nhiều thư viện: lấy mức nặng nhất, liệt kê đủ, không trùng lặp", () => {
    const o = withScripts("https://x/lodash@4.17.15/l.js", "https://x/jquery-1.12.4.min.js", "https://x/jquery-1.12.4.min.js");
    const f = failing(o, id);
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("medium");
    expect(f[0]!.evidence).toHaveLength(2);
  });
  it("im lặng khi không nhận diện được thư viện nào; không có CVE bịa", () => {
    expect(run(baseline(), id)).toHaveLength(0);
    const f = failing(withScripts("https://x/jquery-1.0.0.js"), id)[0]!;
    expect((f.technical ?? "").match(/CVE-\d{4}-\d+/g)!.every((c) => ["CVE-2020-11022", "CVE-2020-11023"].includes(c))).toBe(true);
  });
});

// ---------------------------------------------------------------- Chiếm quyền subdomain
describe("exposure.subdomain-takeover", () => {
  const id = "exposure.subdomain-takeover";
  const page = (body: string, cname: string[] | null = null) => {
    const o = baseline(); o.https!.body = body; o.https!.status = 404; o.dns = { ...o.dns!, cname };
    return o;
  };
  it("dấu vân tay GitHub Pages + CNAME khớp → High, độ tin cậy cao", () => {
    expect(failing(page("<p>There isn't a GitHub Pages site here.</p>", ["user.github.io"]), id)[0]).toMatchObject({ severity: "high", confidence: "high" });
  });
  it("chỉ có dấu vân tay mạnh (chưa thấy CNAME) → Medium, độ tin cậy vừa", () => {
    expect(failing(page("<Code>NoSuchBucket</Code>"), id)[0]).toMatchObject({ severity: "medium", confidence: "medium" });
  });
  it("câu chữ chung chung chỉ tính khi DNS thật sự trỏ tới nhà cung cấp (tránh báo sai)", () => {
    expect(failing(page("<h1>No such app</h1>"), id)).toHaveLength(0);
    expect(failing(page("project not found"), id)).toHaveLength(0);
    expect(failing(page("<h1>No such app</h1>", ["foo.herokuapp.com"]), id)[0]).toMatchObject({ severity: "high" });
    expect(failing(page("project not found", ["x.surge.sh"]), id)).toHaveLength(1);
  });
  it("trang bình thường → đạt", () => expect(run(baseline(), id)[0]!.status).toBe("pass"));
});

// ---------------------------------------------------------------- Trang lỗi lộ thông tin
describe("exposure.error-page-disclosure", () => {
  const id = "exposure.error-page-disclosure";
  const withNotFound = (body: string, status = 404) => { const o = baseline(); o.notFound = rec({ requestedUrl: "https://example.com/zz", finalUrl: "https://example.com/zz", status, body }); return o; };
  it.each([
    ["Traceback (most recent call last):\n  File \"/app/x.py\", line 3", "medium", "python-traceback"],
    ["<b>Warning</b>: Undefined variable $a in /var/www/html/index.php on line 12", "medium", "php-error"],
    ["<br /><b>Warning</b>:  Undefined variable $x in <b>/var/www/html/a.php</b> on line <b>3</b><br />", "medium", "php-error"],
    ["PHP Fatal error: Uncaught Exception in /srv/app/x.php on line 9", "medium", "php-error"],
    ["java.lang.NullPointerException\n\tat com.acme.Foo.bar(Foo.java:42)", "medium", "java-trace"],
    ["You're seeing this error because you have <code>DEBUG = True</code> in your settings", "high", "django-debug"],
    ["Server Error in '/' Application. Version Information: Microsoft .NET Framework", "medium", "aspnet-error"],
    ["<address>Apache/2.4.41 (Ubuntu) Server at example.com Port 80</address>", "low", "apache-banner"],
    ["<center>nginx/1.18.0</center>", "low", "nginx-banner"],
    ["<title>Index of /backup</title>", "medium", "dir-listing"],
    ["Whitelabel Error Page", "low", "spring-whitelabel"],
  ])("%j → %s", (body, sev, key) => {
    const f = failing(withNotFound(body), id);
    expect(keys(f)).toContain(key);
    expect(f.find((x) => x.fingerprint.endsWith(`|${key}`))).toMatchObject({ severity: sev, status: "fail" });
  });
  it("trang 404 bình thường → đạt", () => expect(run(withNotFound("<h1>Không tìm thấy</h1>"), id)[0]!.status).toBe("pass"));
  it("bài hướng dẫn lập trình ở TRANG CHỦ không bị báo nhầm (stack trace chỉ tính trên trang lỗi)", () => {
    const o = baseline();
    o.https!.body = "<h1>Hướng dẫn Python</h1><pre>Traceback (most recent call last):\n  File \"x.py\"</pre><pre>at com.acme.Foo.bar(Foo.java:42)</pre><pre>Warning: x in /var/www/a.php on line 3</pre>";
    expect(failing(o, id)).toHaveLength(0);
  });
  it("dấu hiệu debug đặc trưng vẫn bị bắt ở trang chủ", () => {
    const o = baseline(); o.https!.body = "<title>Index of /uploads</title>";
    expect(keys(failing(o, id))).toContain("dir-listing");
  });
  it("bằng chứng không chứa nguyên trang, chỉ trích ngắn", () => {
    const f = failing(withNotFound("A".repeat(5000) + "Traceback (most recent call last):\n" + "B".repeat(5000)), id)[0]!;
    expect(JSON.stringify(f).length).toBeLessThan(3000);
  });
});

// ---------------------------------------------------------------- DNS & email sâu hơn
describe("config.dns-email-security — kiểm tra sâu", () => {
  const id = "config.dns-email-security";
  const dns = (over: object) => { const o = baseline(); o.dns = { ...o.dns!, ...over }; return o; };
  it("SPF +all → Medium; ?all → Low", () => {
    expect(failing(dns({ spf: "v=spf1 include:x.net +all" }), id).find((f) => f.fingerprint.endsWith("spf-plus-all"))).toMatchObject({ severity: "medium", confidence: "high" });
    expect(failing(dns({ spf: "v=spf1 include:x.net ?all" }), id)[0]).toMatchObject({ severity: "low" });
  });
  it("~all và -all được chấp nhận", () => {
    expect(failing(dns({ spf: "v=spf1 include:x.net ~all" }), id)).toHaveLength(0);
    expect(failing(dns({ spf: "v=spf1 -all" }), id)).toHaveLength(0);
  });
  it("SPF vượt 10 lookup / nhiều bản ghi → Low", () => {
    const many = "v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.net`).join(" ") + " -all";
    expect(spfLookupCount(many)).toBe(11);
    expect(keys(failing(dns({ spf: many }), id))).toContain("spf-lookups");
    expect(keys(failing(dns({ spfRecords: 2 }), id))).toContain("spf-multiple");
  });
  it("spfLookupCount đếm đúng các cơ chế", () => {
    expect(spfLookupCount("v=spf1 a mx include:a.com ip4:1.2.3.4 -all")).toBe(3);
    expect(spfLookupCount("v=spf1 ip4:1.2.3.4 -all")).toBe(0);
    expect(spfLookupCount("v=spf1 exists:%{i}.x.com redirect=_spf.y.com")).toBe(2);
  });
  it("DMARC p=none và pct<100 chỉ là ghi chú; p=reject đạt", () => {
    expect(run(dns({ dmarc: "v=DMARC1; p=none; rua=mailto:a@b.c" }), id).find((f) => f.fingerprint.endsWith("dmarc-policy"))).toMatchObject({ status: "info" });
    expect(run(dns({ dmarc: "v=DMARC1; p=quarantine; pct=25" }), id).find((f) => f.fingerprint.endsWith("dmarc-pct"))).toMatchObject({ status: "info" });
    expect(failing(dns({ dmarc: "v=DMARC1; p=none" }), id)).toHaveLength(0);
  });
  it("DNSSEC: tắt → ghi chú (độ tin cậy vừa); bật → đạt; không tra được → im lặng", () => {
    expect(run(dns({ dnssec: false }), id).find((f) => f.fingerprint.endsWith("|dnssec"))).toMatchObject({ status: "info", severity: "info", confidence: "medium" });
    expect(run(dns({ dnssec: true }), id).some((f) => f.title.includes("DNSSEC") && f.status === "pass")).toBe(true);
    expect(run(dns({ dnssec: undefined }), id).some((f) => f.fingerprint.endsWith("|dnssec"))).toBe(false);
  });
  it("MTA-STS chỉ nhắc khi tên miền có nhận email", () => {
    expect(run(dns({ mtaSts: false, mx: ["mx.a.com"] }), id).some((f) => f.fingerprint.endsWith("mta-sts"))).toBe(true);
    expect(run(dns({ mtaSts: false, mx: null }), id).some((f) => f.fingerprint.endsWith("mta-sts"))).toBe(false);
  });
});

// ---------------------------------------------------------------- Trình theo dõi
describe("privacy.trackers", () => {
  const id = "privacy.trackers";
  it("nhận diện theo host và theo đoạn mã khởi tạo", () => {
    const o = baseline();
    setHtml(o, '<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script src="https://connect.facebook.net/en_US/fbevents.js"></script><script src="https://sp.zalo.me/plugins/sdk.js"></script>');
    expect(detectTrackers(o)).toEqual(["Google Tag Manager", "Meta (Facebook) Pixel", "Zalo Pixel"]);
    const p = baseline(); p.html!.scripts = [{ url: null, inline: true, sameOrigin: true, content: "window.dataLayer=[];function gtag(){} gtag('js',new Date()); fbq('init','1')" }];
    expect(detectTrackers(p)).toEqual(["Google Analytics", "Meta (Facebook) Pixel"]);
  });
  it("chỉ là ghi chú (không trừ điểm) và nhắc Nghị định 13/2023/NĐ-CP", () => {
    const o = baseline(); setHtml(o, '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>');
    const f = run(o, id)[0]!;
    expect(f).toMatchObject({ status: "info", severity: "info" });
    expect(f.explanation).toContain("Nghị định 13/2023/NĐ-CP");
    expect(failing(o, id)).toHaveLength(0);
  });
  it("không tracker → đạt; tên miền cùng site không bị tính", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
    const o = baseline(); setHtml(o, '<script src="https://analytics.example.com/a.js"></script>');
    expect(detectTrackers(o)).toEqual([]);
  });
});

// ---------------------------------------------------------------- Lớp hướng dẫn
function findingsOfBadSite() {
  const o = baseline();
  delete hdr(o)["content-security-policy"]; delete hdr(o)["strict-transport-security"]; delete hdr(o)["x-frame-options"];
  hdr(o)["set-cookie"] = "session=abc; Path=/"; o.https!.chain[0]!.headers = hdr(o);
  setHtml(o, '<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script><img src="http://example.com/a.png">');
  return { o, findings: run(o) };
}

describe("guidance", () => {
  it("mọi luật đều có mức công sức tường minh và tiêu đề dễ hiểu", () => {
    for (const r of ALL_RULES) {
      expect(EFFORT[r.id], `EFFORT thiếu ${r.id}`).toBeDefined();
      expect(PLAIN_TITLES[r.id], `PLAIN_TITLES thiếu ${r.id}`).toBeTruthy();
    }
  });
  it("buildRoadmap gom nhóm theo công sức, sắp theo mức độ và tính điểm tăng thêm đúng", () => {
    const { findings } = findingsOfBadSite();
    const score = calculateScore(findings).score;
    const road = buildRoadmap(findings, score);
    expect(road.map((g) => g.effort)).toEqual(expect.arrayContaining(["quick"]));
    for (const g of road) {
      expect(g.items.every((f) => effortFor(f) === g.effort && f.status === "fail" && f.severity !== "info")).toBe(true);
      const remaining = findings.filter((f) => !g.items.includes(f));
      expect(g.gain).toBe(Math.max(0, calculateScore(remaining).score - score));
    }
    const sevRank = ["critical", "high", "medium", "low"];
    for (const g of road) {
      const ranks = g.items.map((f) => sevRank.indexOf(f.severity));
      expect([...ranks].sort((a, b) => a - b)).toEqual(ranks);
    }
  });
  it("buildSummary nêu điểm, hạng, số vấn đề và việc làm nhanh — bằng tiếng Việt", () => {
    const { findings } = findingsOfBadSite();
    const s = calculateScore(findings);
    const text = buildSummary({ host: "example.com", score: s.score, grade: s.grade, findings, categoryScores: s.categoryScores }).join(" ");
    expect(text).toContain(`example.com đạt ${s.score}/100`);
    expect(text).toContain(`hạng ${s.grade}`);
    expect(text).toMatch(/Có \d+ vấn đề cần xử lý/);
    expect(text).toMatch(/dưới 15 phút/);
  });
  it("site hoàn hảo có tóm tắt tích cực, không bịa vấn đề", () => {
    const f = run(baseline());
    const s = calculateScore(f);
    const text = buildSummary({ host: "ok.com", score: s.score, grade: s.grade, findings: f, categoryScores: s.categoryScores }).join(" ");
    expect(text).toContain("Không phát hiện vấn đề");
  });
  it("toMarkdown đủ mục, không rò bí mật và không chứa giá trị cookie", () => {
    const { findings } = findingsOfBadSite();
    const s = calculateScore(findings);
    const md = toMarkdown({ url: "https://example.com/", host: "example.com", scannedAt: "2026-10-04T00:00:00Z", score: s.score, grade: s.grade, findings, categoryScores: s.categoryScores, disclaimer: "Lưu ý." });
    for (const h of ["# Báo cáo bảo mật — example.com", "## Tóm tắt", "## Điểm theo nhóm", "## Vấn đề cần xử lý", "## Các kiểm tra đạt"]) expect(md).toContain(h);
    expect(md).toContain("**Cách khắc phục:**");
    expect(md).not.toContain("session=abc");
  });
});

// ---------------------------------------------------------------- 100% tiếng Việt
describe("nội dung hiển thị hoàn toàn bằng tiếng Việt", () => {
  /** Từ tiếng Anh phổ biến không được xuất hiện trong văn bản diễn giải (tên header/mã lệnh không nằm trong danh sách). */
  const ENGLISH = /\b(the|is|are|was|and|or|with|without|your|should|missing|please|because|which|this|that|not set|enabled|disabled)\b/i;

  function badSite() {
    const o = baseline();
    delete hdr(o)["content-security-policy"]; delete hdr(o)["strict-transport-security"]; delete hdr(o)["x-frame-options"]; delete hdr(o)["x-content-type-options"]; delete hdr(o)["referrer-policy"]; delete hdr(o)["permissions-policy"];
    Object.assign(hdr(o), { server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3", "set-cookie": "session=abc; Path=/; SameSite=None", "x-frame-options": "ALLOW-FROM x", "x-xss-protection": "1; mode=block" });
    o.https!.chain[0]!.headers = hdr(o);
    Object.assign(o.https!.tls!, { keyType: "rsa", keyBits: 1024, validityDays: 800, wildcard: true, altNames: ["*.example.com"], daysRemaining: 5 });
    o.legacyTls = { tls10: true, tls11: true, h2: false };
    o.http = rec({ requestedUrl: "http://example.com/", finalUrl: "http://example.com/" });
    setHtml(o, '<form action="http://example.com/login" method="get"><input type="password"></form><script src="http://x.net/a.js"></script><script src="https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"></script><script src="https://www.googletagmanager.com/gtag/js"></script><meta http-equiv="refresh" content="0;url=https://evil.org/">');
    o.cors = { testedOrigin: "https://p.invalid", status: 200, acao: "https://p.invalid", acac: "true", vary: null };
    o.sourceMaps = [{ scriptUrl: "u", mapUrl: "https://example.com/a.js.map", exposed: true, status: 200 }];
    o.files.securityTxt = { url: "u", present: false, status: 404, contentType: "", body: "" };
    o.files.robots = { url: "u", present: true, status: 200, contentType: "text/plain", body: "Disallow: /admin-backup" };
    o.notFound = rec({ status: 404, body: "Traceback (most recent call last):" });
    o.altHost = { host: "www.example.com", record: rec({ certError: { code: "CERT_HAS_EXPIRED", message: "x" } }) };
    o.dns = { domain: "example.com", caa: [], spf: "v=spf1 +all", spfRecords: 2, dmarc: "v=DMARC1; p=none", cname: ["u.github.io"], mx: ["mx"], dnssec: false, mtaSts: false };
    o.scripts = [{ url: "https://example.com/a.js", inline: false, sameOrigin: true, content: "var k='" + "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2';" }];
    o.https!.body = "<p>There isn't a GitHub Pages site here.</p>";
    return o;
  }

  it("diễn giải của mọi phát hiện (title/summary/explanation/cách khắc phục) không chứa tiếng Anh", () => {
    const findings = run(badSite());
    expect(findings.length).toBeGreaterThan(30);
    const offenders: string[] = [];
    for (const f of findings) {
      const texts = [f.title, f.summary, f.explanation, f.remediation?.summary ?? "", ...(f.remediation?.steps ?? [])];
      for (const t of texts) {
        // bỏ phần mã/giá trị trong dấu nháy/backtick: chúng là chuỗi kỹ thuật
        const prose = t.replace(/`[^`]*`|"[^"]*"|'[^']*'|\([^)]*\)/g, " ");
        if (ENGLISH.test(prose)) offenders.push(`${f.ruleId}: ${t.slice(0, 120)}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("phủ gần hết các luật (≥ 30 luật có kết quả) để test trên có ý nghĩa", () => {
    expect(new Set(run(badSite()).map((f) => f.ruleId)).size).toBeGreaterThanOrEqual(30);
  });

  it("nhãn danh mục / mức độ đều có và là tiếng Việt", () => {
    for (const c of CATEGORIES) expect(CATEGORY_LABEL[c]).toBeTruthy();
    expect(Object.values(SEV_LABEL)).toEqual(["Nghiêm trọng", "Cao", "Trung bình", "Thấp", "Thông tin"]);
  });

  it("các luật chạy trên site không có lỗi vẫn không phát sinh tiếng Anh", () => {
    for (const f of run(baseline())) expect(ENGLISH.test([f.title, f.summary, f.explanation].join(" ").replace(/`[^`]*`|"[^"]*"|\([^)]*\)/g, " ")), `${f.ruleId}: ${f.summary}`).toBe(false);
  });
});

void GOOD_HEADERS;

describe("headers.deprecated", () => {
  const id = "headers.deprecated";
  it("HPKP → Medium; Expect-CT/Feature-Policy → Info", () => {
    const o = baseline();
    const h = hdr(o);
    Object.assign(h, { "public-key-pins": 'pin-sha256="x"; max-age=100', "expect-ct": "max-age=86400", "feature-policy": "camera 'none'" });
    const sev = new Set(run(o, id).map((f) => f.severity));
    expect(sev.has("medium")).toBe(true);
    expect(sev.has("info")).toBe(true);
  });
  it("không có header lỗi thời → đạt", () => {
    expect(run(baseline(), id)[0]!.status).toBe("pass");
  });
});
