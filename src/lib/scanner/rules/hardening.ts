import { headerFix } from "../remediation";
import type { Finding, Rule } from "../types";
import { header, headerEvidence, isHtml, livePage, makeFinding, MDN, OWASP, pass, truncate } from "../util";
import { collectCookies, SESSION_NAME } from "./cookies";

/**
 * Luật "tăng cường" (hardening): phân tích sâu hơn các dữ liệu đã thu. Không luật nào gửi request riêng
 * (trừ OPTIONS và vài tệp nhạy cảm cố định đã thu sẵn trong collect-core). Mức trừ điểm nhỏ, nhưng cộng dồn.
 */

// ---------------------------------------------------------------- HSTS preload
const hstsPreload: Rule = {
  id: "tls.hsts-preload",
  title: "HSTS đủ điều kiện danh sách preload",
  category: "Transport Security",
  run(obs) {
    const h = obs.https;
    if (!h || h.error || h.status === null) return [];
    const v = header(h.headers, "strict-transport-security");
    if (!v) return []; // đã báo ở tls.hsts
    const age = Number(/max-age\s*=\s*"?(\d+)"?/i.exec(v)?.[1] ?? NaN);
    if (Number.isNaN(age) || age < 15_552_000) return [];
    const sub = /includeSubDomains/i.test(v), pre = /(^|;)\s*preload\s*(;|$)/i.test(v);
    const refs = [{ title: "hstspreload.org", url: "https://hstspreload.org/" }, MDN("Web/HTTP/Reference/Headers/Strict-Transport-Security", "MDN: Strict-Transport-Security")];
    if (pre && (!sub || age < 31_536_000)) {
      return [makeFinding({ ruleId: this.id, key: "invalid", title: "Cờ HSTS preload không hợp lệ", category: this.category, severity: "low", confidence: "high", status: "fail", affectedUrl: h.finalUrl, references: refs,
        summary: "Header có preload nhưng thiếu includeSubDomains hoặc max-age dưới 1 năm nên không được nhận vào danh sách preload.", explanation: "Danh sách preload yêu cầu max-age ≥ 31536000, includeSubDomains và preload. Thiếu một điều kiện thì cờ preload không có tác dụng.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")], remediation: headerFix("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload", obs.platforms) })];
    }
    if (!pre) {
      return [makeFinding({ ruleId: this.id, key: "missing", title: "Chưa sẵn sàng danh sách HSTS preload", category: this.category, severity: "low", confidence: "low", status: "fail", affectedUrl: h.finalUrl, references: refs,
        summary: "HSTS đã bật nhưng chưa có preload, nên lần truy cập ĐẦU TIÊN của khách vẫn có thể đi qua HTTP.", explanation: "Danh sách preload được cài sẵn trong trình duyệt: khách không cần từng ghé website mới được bảo vệ. Đây là bước tăng cường cuối cùng, nhưng khó gỡ nếu sau này cần quay lại HTTP nên chỉ làm khi mọi tên miền con đều chạy HTTPS.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")],
        remediation: { ...headerFix("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload", obs.platforms), steps: ["Chắc chắn MỌI tên miền con đều chạy HTTPS trước khi thêm includeSubDomains + preload.", "Sau khi triển khai header, gửi tên miền tại https://hstspreload.org/."] } })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: h.finalUrl, summary: "HSTS có max-age ≥ 1 năm, includeSubDomains và preload.", explanation: "Đủ điều kiện nhận vào danh sách preload của trình duyệt.", evidence: [headerEvidence(h.headers, "strict-transport-security")], references: refs })];
  },
};

// ---------------------------------------------------------------- bộ mã hoá TLS
const cipherSuite: Rule = {
  id: "tls.cipher-suite",
  title: "Bộ mã hoá TLS hiện đại",
  category: "Transport Security",
  run(obs) {
    const t = obs.https?.tls;
    if (!t?.cipher || !t.protocol) return [];
    const url = obs.https!.finalUrl;
    const refs = [{ title: "Mozilla: Server Side TLS", url: "https://wiki.mozilla.org/Security/Server_Side_TLS" }];
    const ev = [`Giao thức: ${t.protocol}`, `Bộ mã hoá thương lượng: ${t.cipher}`];
    if (t.protocol === "TLSv1.3") return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: url, summary: "TLS 1.3: toàn bộ bộ mã hoá đều là AEAD và có forward secrecy.", explanation: "Không còn bộ mã hoá yếu để lựa chọn.", evidence: ev, references: refs })];
    const weak = /(RC4|3DES|DES-CBC|NULL|EXPORT|MD5|anon)/i.test(t.cipher);
    const cbc = !/(GCM|CCM|POLY1305)/i.test(t.cipher); // OpenSSL gọi CBC là “…-AES128-SHA”: bộ nào không phải AEAD thì là CBC/stream
    const fs = /^(ECDHE|DHE|EDH)/i.test(t.cipher);
    if (weak) return [makeFinding({ ruleId: this.id, key: "weak", title: "Bộ mã hoá TLS yếu được thương lượng", category: this.category, severity: "high", confidence: "high", status: "fail", affectedUrl: url, references: refs,
      summary: `Kết nối dùng ${t.cipher}, một bộ mã hoá đã bị coi là yếu.`, explanation: "Các thuật toán như RC4/3DES/DES có thể bị bẻ khoá hoặc tấn công thống kê, làm lộ nội dung truyền đi.", evidence: ev,
      remediation: { summary: "Chỉ bật bộ mã hoá AEAD (AES-GCM, ChaCha20-Poly1305) có ECDHE.", snippets: [] } })];
    const issues = [cbc ? "dùng chế độ CBC (không phải AEAD)" : "", !fs ? "không có forward secrecy (không ECDHE/DHE)" : ""].filter(Boolean);
    if (issues.length) return [makeFinding({ ruleId: this.id, key: "legacy", title: "Bộ mã hoá TLS 1.2 chưa tối ưu", category: this.category, severity: !fs ? "medium" : "low", confidence: "medium", status: "fail", affectedUrl: url, references: refs,
      summary: `${t.cipher}: ${issues.join("; ")}.`, explanation: "Không có forward secrecy thì khoá riêng bị lộ sau này sẽ giải mã được cả lưu lượng đã ghi lại trước đó; CBC từng bị khai thác trong các tấn công kiểu padding oracle.",
      technical: "Chỉ thấy bộ mã hoá ĐƯỢC THƯƠNG LƯỢNG với trình duyệt hiện đại, không liệt kê hết các bộ máy chủ chấp nhận.", evidence: ev,
      remediation: { summary: "Ưu tiên ECDHE + AES-GCM/ChaCha20 và bật TLS 1.3.", snippets: [] } })];
    return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: url, summary: `${t.cipher}: AEAD có forward secrecy.`, explanation: "Bộ mã hoá thương lượng là loại hiện đại.", evidence: ev, references: refs })];
  },
};

// ---------------------------------------------------------------- chính sách cache
const cachePolicy: Rule = {
  id: "headers.cache-policy",
  title: "Chính sách bộ nhớ đệm của trang HTML",
  category: "Headers",
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const cc = header(p.headers, "cache-control");
    const cookies = (p.chain.at(-1)?.headers["set-cookie"]);
    const hasCookie = Array.isArray(cookies) ? cookies.length > 0 : !!cookies;
    const refs = [MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching"), OWASP("HTTP_Headers_Cheat_Sheet.html", "OWASP HTTP Headers")];
    if (!cc) return [makeFinding({ ruleId: this.id, key: "missing", title: "Trang HTML không khai báo Cache-Control", category: this.category, severity: "low", confidence: "low", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: "Phản hồi không có Cache-Control nên proxy/trình duyệt tự quyết định có lưu hay không.", explanation: "Nếu trang có nội dung riêng tư, bộ nhớ đệm dùng chung có thể lưu và phát lại cho người khác. Luôn khai báo rõ ràng chính sách mong muốn.",
      evidence: [headerEvidence(p.headers, "cache-control")], remediation: headerFix("Cache-Control", "no-cache", obs.platforms, "Dùng no-cache (luôn xác thực lại) hoặc no-store cho trang riêng tư; chỉ dùng public, max-age=… cho nội dung công khai.") })];
    const shared = /(^|,)\s*(public|s-maxage=\d+|max-age=([1-9]\d*))/i.test(cc) && !/(no-store|private|no-cache)/i.test(cc);
    if (hasCookie && shared) return [makeFinding({ ruleId: this.id, key: "cookie-cacheable", title: "Trang đặt cookie nhưng cho phép bộ nhớ đệm dùng chung", category: this.category, severity: "medium", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: `Cache-Control "${truncate(cc, 80)}" cho phép lưu đệm trong khi phản hồi đặt cookie.`, explanation: "Proxy hoặc CDN có thể lưu phản hồi cùng Set-Cookie rồi phát cho người dùng khác, làm lộ phiên đăng nhập.",
      evidence: [headerEvidence(p.headers, "cache-control"), "Phản hồi có Set-Cookie"], remediation: headerFix("Cache-Control", "private, no-store", obs.platforms) })];
    return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: p.finalUrl, summary: "Cache-Control được khai báo rõ ràng.", explanation: "Chính sách lưu đệm không phụ thuộc vào đoán của proxy.", evidence: [headerEvidence(p.headers, "cache-control")], references: refs })];
  },
};

// ---------------------------------------------------------------- header gỡ lỗi / nội bộ
const DEBUG_HEADERS: { re: RegExp; sev: "medium" | "low"; why: string }[] = [
  { re: /^x-debug-token(-link)?$/, sev: "medium", why: "Symfony Profiler đang bật: lộ đường dẫn tới trang gỡ lỗi chứa cấu hình, truy vấn DB và biến môi trường" },
  { re: /^x-(backend|upstream|real)-server$|^x-server$|^x-host$|^x-forwarded-server$/, sev: "low", why: "tiết lộ tên/địa chỉ máy chủ phía sau" },
  { re: /^x-runtime$|^x-request-start$|^x-powered-by-plesk$|^x-turbo-charged-by$/, sev: "low", why: "tiết lộ nền tảng/thời gian xử lý nội bộ" },
  { re: /^x-generator$|^x-aspnetmvc-version$/, sev: "low", why: "tiết lộ phần mềm và phiên bản" },
];
const PRIVATE_IP_IN_HEADER = /(?<![\d.])(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])/;
const debugHeaders: Rule = {
  id: "config.debug-headers",
  title: "Không lộ header gỡ lỗi hoặc địa chỉ nội bộ",
  category: "Configuration",
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const out: Finding[] = [];
    const refs = [OWASP("HTTP_Headers_Cheat_Sheet.html", "OWASP HTTP Headers")];
    for (const [name, raw] of Object.entries(p.headers)) {
      const value = Array.isArray(raw) ? raw.join(", ") : raw;
      const hit = DEBUG_HEADERS.find((d) => d.re.test(name));
      const ip = name !== "set-cookie" ? PRIVATE_IP_IN_HEADER.exec(value)?.[1] : undefined;
      if (hit) out.push(makeFinding({ ruleId: this.id, key: name, title: `Header ${name} lộ thông tin nội bộ`, category: this.category, severity: hit.sev, confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Phản hồi có "${name}": ${hit.why}.`, explanation: "Header gỡ lỗi chỉ nên bật ở môi trường phát triển. Trên production chúng giúp kẻ tấn công hiểu kiến trúc và tìm điểm yếu nhanh hơn.", evidence: [`${name}: ${truncate(value, 120)}`], remediation: null }));
      else if (ip) out.push(makeFinding({ ruleId: this.id, key: `ip:${name}`, title: `Header ${name} chứa địa chỉ IP nội bộ`, category: this.category, severity: "low", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Giá trị header ${name} chứa địa chỉ nội bộ ${ip}.`, explanation: "Địa chỉ IP riêng cho biết cấu trúc mạng phía sau proxy/load balancer.", evidence: [`${name}: ${truncate(value, 120)}`], remediation: null }));
    }
    if (out.length === 0) return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: p.finalUrl, summary: "Không thấy header gỡ lỗi hay địa chỉ IP nội bộ trong phản hồi.", explanation: "Kiến trúc phía sau không bị lộ qua header.", evidence: [], references: refs })];
    return out;
  },
};

// ---------------------------------------------------------------- phương thức HTTP
const httpMethods: Rule = {
  id: "config.http-methods",
  title: "Phương thức HTTP được công bố",
  category: "Configuration",
  run(obs) {
    const m = obs.methods;
    if (!m) return [];
    const url = obs.page?.finalUrl ?? obs.target.url;
    const refs = [MDN("Web/HTTP/Reference/Methods", "MDN: HTTP methods"), { title: "OWASP WSTG: Test HTTP methods", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods" }];
    const allowed = (m.allow ?? "").split(",").map((x) => x.trim().toUpperCase()).filter(Boolean);
    const ev = [`OPTIONS ${url} → ${m.status}`, `Allow: ${m.allow ?? "(không có)"}`];
    const trace = allowed.filter((x) => x === "TRACE" || x === "TRACK");
    if (trace.length) return [makeFinding({ ruleId: this.id, key: "trace", title: "Máy chủ công bố phương thức TRACE/TRACK", category: this.category, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
      summary: `Header Allow có ${trace.join(", ")}.`, explanation: "TRACE phản chiếu lại nguyên request (kể cả header nhạy cảm) và là nền tảng của tấn công Cross-Site Tracing. Hiếm khi cần ở production.", evidence: ev,
      remediation: { summary: "Tắt TRACE/TRACK.", snippets: [] } })];
    const risky = allowed.filter((x) => ["PUT", "DELETE", "PATCH", "CONNECT"].includes(x));
    if (risky.length) return [makeFinding({ ruleId: this.id, key: "write-methods", title: "Trang chủ công bố phương thức ghi", category: this.category, severity: "low", confidence: "low", status: "fail", affectedUrl: url, references: refs,
      summary: `Header Allow của trang chủ có ${risky.join(", ")}.`, explanation: "Phương thức ghi/xoá không nên được công bố ở trang công khai. Đây chỉ là công bố (chúng tôi không gọi thử); hãy xác nhận máy chủ thực sự yêu cầu xác thực cho các phương thức này.", evidence: ev,
      remediation: { summary: "Giới hạn phương thức ở mức cần thiết (GET, HEAD, OPTIONS cho trang tĩnh).", snippets: [] } })];
    return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: url, summary: m.allow ? "Chỉ công bố các phương thức an toàn." : "Máy chủ không công bố danh sách phương thức.", explanation: "Không có TRACE hay phương thức ghi bị công bố ở trang chủ.", evidence: ev, references: refs })];
  },
};

// ---------------------------------------------------------------- form gửi sang origin khác
const formTargets: Rule = {
  id: "browser.form-targets",
  title: "Form mật khẩu chỉ gửi về chính website",
  category: "Browser Security",
  run(obs) {
    const html = obs.html, p = obs.page;
    if (!html || !p) return [];
    const origin = new URL(p.finalUrl).origin;
    const pw = html.forms.filter((f) => f.hasPassword);
    if (pw.length === 0) return [];
    const cross = pw.filter((f) => { try { return new URL(f.action).origin !== origin; } catch { return false; } });
    const refs = [OWASP("Authentication_Cheat_Sheet.html", "OWASP Authentication")];
    if (cross.length === 0) return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: p.finalUrl, summary: "Mọi form có ô mật khẩu đều gửi về cùng origin.", explanation: "Mật khẩu không bị gửi sang bên thứ ba.", evidence: pw.map((f) => `action: ${f.action}`), references: refs })];
    return cross.map((f) => makeFinding({ ruleId: this.id, key: `x:${new URL(f.action).host}`, title: "Form mật khẩu gửi sang website khác", category: this.category, severity: "medium", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: `Form có ô mật khẩu gửi tới ${new URL(f.action).origin}, khác với ${origin}.`, explanation: "Thông tin đăng nhập rời khỏi website của bạn. Hợp lệ nếu là dịch vụ đăng nhập tập trung bạn tin cậy; ngược lại có thể là dấu hiệu mã bị chèn để đánh cắp mật khẩu.",
      evidence: [`action: ${f.action}`, `trang: ${p.finalUrl}`], remediation: { summary: "Kiểm tra đích gửi form là có chủ đích, và đặt CSP form-action giới hạn đúng đích đó.", snippets: [] } }));
  },
};

// ---------------------------------------------------------------- tiền tố cookie
const cookiePrefix: Rule = {
  id: "cookies.prefix",
  title: "Cookie phiên dùng tiền tố __Host-/__Secure-",
  category: "Cookies & Sessions",
  run(obs) {
    const session = collectCookies(obs).filter((c) => SESSION_NAME.test(c.name));
    if (session.length === 0) return [];
    const bare = session.filter((c) => !/^__(Host|Secure)-/.test(c.name));
    const refs = [MDN("Web/HTTP/Guides/Cookies#cookie_prefixes", "MDN: Cookie prefixes")];
    if (bare.length === 0) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: "Cookie phiên dùng tiền tố bảo vệ của trình duyệt.", explanation: "Trình duyệt từ chối cookie giả mạo từ tên miền con hoặc kênh không an toàn.", evidence: session.map((c) => c.name), references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Cookie phiên chưa dùng tiền tố __Host-", category: this.category, severity: "low", confidence: "low", status: "fail", references: refs,
      summary: `${bare.length} cookie giống cookie phiên không dùng tiền tố (${bare.slice(0, 3).map((c) => c.name).join(", ")}).`, explanation: "Tiền tố __Host- buộc cookie là Secure, Path=/ và không có Domain, ngăn tên miền con hoặc kênh HTTP ghi đè cookie phiên (cookie tossing).",
      technical: "Độ tin cậy thấp vì nhận diện cookie phiên dựa trên tên.", evidence: bare.map((c) => `${c.name}=<đã che>`), remediation: { summary: "Đổi tên cookie phiên thành __Host-<tên> (kèm Secure; Path=/; không Domain).", snippets: [] } })];
  },
};

export const hardeningRules: Rule[] = [hstsPreload, cipherSuite, cachePolicy, debugHeaders, httpMethods, formTargets, cookiePrefix];
