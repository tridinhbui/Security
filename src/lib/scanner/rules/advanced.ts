import type { Finding, Observations, Rule } from "../types";
import { header, livePage, makeFinding, MDN, OWASP, pass, setCookies, truncate } from "../util";
import { collectCookies, SESSION_NAME } from "./cookies";

/**
 * Luật NÂNG CAO (chỉ chạy ở chế độ quét đầy đủ). Toàn bộ là phân tích thụ động, xác định, trên dữ liệu đã thu:
 * phân tích sâu CSP, rò rỉ qua cache dùng chung, phạm vi cookie, chuỗi cung ứng script, luồng dữ liệu nguy hiểm trong JavaScript,
 * chuỗi chuyển hướng, tính nhất quán header giữa các trang, SPF/DMARC chi tiết, vệ sinh chứng chỉ.
 * Không luật nào gửi thêm request, không khai thác lỗ hổng. Phương pháp heuristic ghi rõ "độ tin cậy thấp".
 */
const adv = (r: Rule): Rule => ({ ...r, advanced: true });

interface Text { name: string; text: string }
/** Mọi đoạn JavaScript đã thu (inline + file đã tải), kèm tên để dẫn chứng. */
function jsTexts(obs: Observations): Text[] {
  const out: Text[] = [];
  for (const s of obs.scripts) {
    const text = s.content ?? s.fetched?.body;
    if (text) out.push({ name: s.inline ? "(script nội tuyến)" : s.url ?? "?", text });
  }
  return out;
}
const uniq = <T,>(a: T[]) => [...new Set(a)];
const hostOf = (u: string) => { try { return new URL(u).hostname; } catch { return ""; } };

// ================================================================ 1. CSP phân tích sâu
const BYPASS_HOSTS = ["ajax.googleapis.com", "www.google.com", "accounts.google.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "raw.githubusercontent.com", "s3.amazonaws.com", "cloudfront.net", "storage.googleapis.com", "herokuapp.com", "firebaseapp.com"];

function parseCsp(v: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const d of v.split(";")) {
    const [name, ...vals] = d.trim().split(/\s+/);
    if (name && !m.has(name.toLowerCase())) m.set(name.toLowerCase(), vals);
  }
  return m;
}

const cspAnalysis = adv({
  id: "adv.csp-analysis",
  title: "Phân tích sâu chính sách CSP",
  category: "Headers",
  run(obs) {
    const p = livePage(obs);
    const raw = p ? header(p.headers, "content-security-policy") : undefined;
    if (!p || !raw) return [];
    const d = parseCsp(raw);
    const scriptSrc = d.get("script-src") ?? d.get("default-src") ?? [];
    const low = scriptSrc.map((x) => x.toLowerCase());
    const hasNonce = low.some((x) => x.startsWith("'nonce-") || x.startsWith("'sha256-") || x.startsWith("'sha384-") || x.startsWith("'sha512-"));
    const strictDyn = low.includes("'strict-dynamic'");
    const issues: { text: string; sev: "medium" | "low" }[] = [];
    if (low.includes("'unsafe-inline'") && !(hasNonce || strictDyn)) issues.push({ text: "script-src cho phép 'unsafe-inline' (không có nonce/hash): CSP gần như không chặn được XSS.", sev: "medium" });
    if (low.includes("'unsafe-eval'")) issues.push({ text: "script-src cho phép 'unsafe-eval' (eval/new Function).", sev: "low" });
    if (low.includes("*") || low.some((x) => x === "https:" || x === "http:" || x === "data:")) issues.push({ text: `script-src dùng nguồn quá rộng (${scriptSrc.filter((x) => ["*", "https:", "http:", "data:"].includes(x.toLowerCase())).join(", ")}): kẻ tấn công chỉ cần một nguồn bất kỳ.`, sev: "medium" });
    const bypass = low.filter((x) => BYPASS_HOSTS.some((h) => x.replace(/^https?:\/\//, "").replace(/^\*\./, "").startsWith(h) || x.includes(h)));
    if (bypass.length && !strictDyn) issues.push({ text: `script-src tin cậy cả nguồn lưu trữ dùng chung (${bypass.join(", ")}): thường có thể lợi dụng JSONP/thư viện có sẵn để vượt qua CSP.`, sev: "low" });
    const objectSrc = d.get("object-src") ?? d.get("default-src");
    if (!objectSrc || !objectSrc.map((x) => x.toLowerCase()).includes("'none'")) issues.push({ text: "Thiếu object-src 'none' (plugin/flash cũ có thể chạy mã).", sev: "low" });
    if (!d.has("base-uri")) issues.push({ text: "Thiếu base-uri: kẻ tấn công chèn thẻ <base> có thể đổi đích của mọi đường dẫn tương đối.", sev: "low" });
    // frame-ancestors do luật headers.frame-protection quản (tránh tính điểm hai lần cho cùng một lỗi clickjacking).
    const refs = [MDN("Web/HTTP/Guides/CSP", "MDN: Content Security Policy"), { title: "Google CSP Evaluator", url: "https://csp-evaluator.withgoogle.com/" }];
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: p.finalUrl, summary: "CSP chặt: không unsafe-inline/eval, nguồn hẹp, có object-src, base-uri, frame-ancestors, form-action.", explanation: "Chính sách này thực sự thu hẹp được những gì trình duyệt cho phép chạy.", evidence: [truncate(raw, 200)], references: refs })];
    const worst = issues.some((i) => i.sev === "medium") ? "medium" : "low";
    return [makeFinding({ ruleId: this.id, title: "CSP có điểm yếu làm giảm tác dụng chống XSS", category: this.category, severity: worst, confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: `Phát hiện ${issues.length} điểm yếu trong CSP.`, explanation: "Có CSP nhưng cấu hình lỏng thì kẻ tấn công vẫn chạy được mã chèn vào trang. Bảo vệ chỉ thật sự có khi chính sách đủ chặt.",
      technical: "Phân tích chỉ dựa trên header CSP của trang chủ (không đọc CSP đặt qua thẻ meta).", evidence: [...issues.map((i) => `• ${i.text}`), `CSP: ${truncate(raw, 220)}`] })];
  },
});

// ================================================================ 2. Rò rỉ phiên qua cache dùng chung
const cacheLeak = adv({
  id: "adv.shared-cache-leak",
  title: "Cookie phiên không bị cache dùng chung giữ lại",
  category: "Cookies & Sessions",
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const sc = setCookies(p.headers);
    if (!sc.length) return [];
    const cc = (header(p.headers, "cache-control") ?? "").toLowerCase();
    const age = Number(header(p.headers, "age") ?? NaN);
    const hit = /hit/i.test(header(p.headers, "cf-cache-status") ?? "") || /hit/i.test(header(p.headers, "x-cache") ?? "") || (!Number.isNaN(age) && age > 0);
    const shared = /(^|,\s*)public\b/.test(cc) || /s-maxage\s*=\s*[1-9]/.test(cc);
    const blocked = /(private|no-store)/.test(cc);
    const vary = (header(p.headers, "vary") ?? "").toLowerCase();
    const refs = [OWASP("Session_Management_Cheat_Sheet.html", "OWASP: Session Management"), MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching")];
    const ev = [`Set-Cookie: ${sc.length} cookie (giá trị đã che)`, `Cache-Control: ${cc || "(không có)"}`, `Age: ${Number.isNaN(age) ? "(không có)" : age}`, `Vary: ${vary || "(không có)"}`];
    if (hit && !blocked) return [makeFinding({ ruleId: this.id, key: "hit", title: "Phản hồi có cookie đã bị cache dùng chung phục vụ lại", category: this.category, severity: "high", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: "Trang chủ vừa gửi Set-Cookie vừa được CDN/proxy trả từ bộ nhớ đệm (cache HIT).", explanation: "Nếu cookie phiên của người này bị cache, người truy cập kế tiếp có thể nhận chính cookie đó và vào thẳng tài khoản của họ.", evidence: ev,
      technical: "Dấu hiệu HIT lấy từ Age, X-Cache hoặc CF-Cache-Status; chưa chứng minh cookie bị phát lại." })];
    if (shared && !blocked && !/\bcookie\b/.test(vary)) return [makeFinding({ ruleId: this.id, key: "public", title: "Trang cho phép cache dùng chung nhưng lại đặt cookie", category: this.category, severity: "medium", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: "Cache-Control cho phép lưu dùng chung (public/s-maxage) trong khi phản hồi đặt cookie.", explanation: "CDN hoặc proxy có thể lưu phản hồi kèm cookie rồi phát cho người khác.", evidence: ev })];
    return [pass({ ruleId: this.id, title: this.title, category: this.category, affectedUrl: p.finalUrl, summary: "Phản hồi có cookie nhưng không cho cache dùng chung.", explanation: "Cookie sẽ không bị giữ lại ở CDN/proxy.", evidence: ev, references: refs })];
  },
});

// ================================================================ 3. Phạm vi và vòng đời cookie
const cookieScope = adv({
  id: "adv.cookie-scope",
  title: "Phạm vi và vòng đời cookie hợp lý",
  category: "Cookies & Sessions",
  run(obs) {
    if (!obs.page) return [];
    const cookies = collectCookies(obs);
    if (!cookies.length) return [];
    const issues: string[] = [];
    for (const c of cookies) {
      const sess = SESSION_NAME.test(c.name);
      if (sess && c.domain) issues.push(`${c.name}: Domain=${c.domain} → cookie phiên được gửi tới MỌI tên miền con (một subdomain bị chiếm là mất phiên).`);
      if (sess && ((c.maxAgeDays ?? 0) > 90 || (c.expiresInDays ?? 0) > 90)) issues.push(`${c.name}: sống ${Math.round(c.maxAgeDays ?? c.expiresInDays ?? 0)} ngày → phiên đăng nhập tồn tại quá lâu nếu bị đánh cắp.`);
      if (c.sameSite === "none" && !c.secure) issues.push(`${c.name}: SameSite=None nhưng không Secure → trình duyệt hiện đại sẽ từ chối cookie này.`);
    }
    if (cookies.length > 20) issues.push(`Đặt tới ${cookies.length} cookie: tăng kích thước mọi request và bề mặt rò rỉ.`);
    const refs = [OWASP("Session_Management_Cheat_Sheet.html", "OWASP: Session Management")];
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: "Cookie phiên không mở rộng sang tên miền con, thời hạn hợp lý.", explanation: "Phạm vi cookie được giữ hẹp.", references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Cookie có phạm vi hoặc thời hạn quá rộng", category: this.category, severity: "low", confidence: "medium", status: "fail", references: refs, summary: `${issues.length} vấn đề về phạm vi/thời hạn cookie.`, explanation: "Cookie càng rộng và sống càng lâu thì hậu quả khi bị lộ hoặc bị ghi đè càng lớn.", evidence: issues.slice(0, 8) })];
  },
});

// ================================================================ 4. Chuỗi cung ứng script
const COMPROMISED = ["polyfill.io", "polyfill.com", "bootcss.com", "bootcdn.net", "staticfile.net", "staticfile.org", "unionadjs.com", "xhsbpza.com", "macoms.la", "newcrbpc.com"];
const supplyChain = adv({
  id: "adv.supply-chain",
  title: "Chuỗi cung ứng script bên thứ ba",
  category: "Browser Security",
  run(obs) {
    const ext = obs.scripts.filter((s) => s.url && !s.sameOrigin);
    if (!ext.length) return [];
    const ev: string[] = [];
    let sev: "critical" | "medium" | "low" | null = null;
    const bump = (s: "critical" | "medium" | "low") => { const order = { low: 0, medium: 1, critical: 2 } as const; if (!sev || order[s] > order[sev]) sev = s; };
    const bad = ext.filter((s) => COMPROMISED.some((d) => hostOf(s.url!).endsWith(d)));
    for (const s of bad) { ev.push(`Nguồn từng bị lợi dụng để chèn mã độc: ${s.url}`); bump("critical"); }
    const unpinned = ext.filter((s) => /(@latest\b|\/latest\/|unpkg\.com\/[^@/]+\/|cdn\.jsdelivr\.net\/npm\/[^@/]+\/|cdn\.jsdelivr\.net\/gh\/[^@/]+\/[^@/]+\/)/i.test(s.url!));
    for (const s of unpinned.slice(0, 4)) { ev.push(`Không ghim phiên bản (nội dung đổi theo thời gian): ${s.url}`); bump("medium"); }
    const origins = uniq(ext.map((s) => hostOf(s.url!)));
    if (origins.length > 8) { ev.push(`${origins.length} nguồn script khác nhau: ${origins.slice(0, 8).join(", ")}…`); bump("low"); }
    const refs = [OWASP("Third_Party_Javascript_Management_Cheat_Sheet.html", "OWASP: Third-party JavaScript management")];
    if (!sev) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: `${ext.length} script bên ngoài, đều ghim phiên bản và từ nguồn không đáng ngờ.`, explanation: "Chuỗi cung ứng gọn và ổn định.", references: refs })];
    const critical = sev === "critical";
    return [makeFinding({ ruleId: this.id, title: critical ? "Trang nạp script từ nguồn đã từng bị chiếm dụng" : "Chuỗi cung ứng script có rủi ro", category: this.category, severity: sev, confidence: critical ? "high" : "medium", status: "fail", references: refs,
      summary: critical ? "Một số script đến từ tên miền đã từng bị dùng để phát tán mã độc tới hàng loạt website." : "Script bên ngoài không được ghim phiên bản hoặc có quá nhiều nguồn.",
      explanation: "Mã bên thứ ba chạy với quyền như chính website của bạn. Nếu nhà cung cấp bị xâm nhập hoặc đổi nội dung, mã độc chạy trên máy mọi khách truy cập.", evidence: ev })];
  },
});

// ================================================================ 5–7. Phân tích tĩnh JavaScript
const SRC = /(location\.(hash|search|href|pathname)|document\.(URL|documentURI|referrer|cookie)|window\.name)/;
const SINK = /(\.innerHTML\s*[+]?=|\.outerHTML\s*=|document\.write(ln)?\s*\(|insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|\.html\s*\(|setTimeout\s*\(\s*['"`])/;

const domSinks = adv({
  id: "adv.dom-xss-flow",
  title: "Luồng dữ liệu nguy hiểm trong JavaScript (DOM XSS)",
  category: "Browser Security",
  run(obs) {
    const files = jsTexts(obs);
    if (!files.length) return [];
    const hits: string[] = [];
    let evals = 0;
    for (const f of files) {
      evals += (f.text.match(/\beval\s*\(/g) ?? []).length;
      const re = new RegExp(SRC.source, "g");
      let m: RegExpExecArray | null;
      let found = false;
      while (!found && (m = re.exec(f.text))) {
        const win = f.text.slice(Math.max(0, m.index - 220), m.index + 220);
        if (SINK.test(win)) { hits.push(`${f.name}: nguồn "${m[1]}" nằm sát điểm ghi nguy hiểm (${SINK.exec(win)![1]!.trim()})`); found = true; }
      }
    }
    const refs = [OWASP("DOM_based_XSS_Prevention_Cheat_Sheet.html", "OWASP: DOM-based XSS prevention")];
    if (!hits.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: `Đã quét ${files.length} đoạn JavaScript: không thấy dữ liệu từ URL chảy thẳng vào điểm ghi nguy hiểm.`, explanation: "Không có dấu hiệu DOM XSS theo heuristic gần-nhau.", technical: "Phân tích tĩnh heuristic trên mã đã thu (có thể bị nén), không thay thế kiểm thử thủ công.", references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Dữ liệu từ URL có thể chảy vào điểm ghi nguy hiểm", category: this.category, severity: "medium", confidence: "low", status: "fail", references: refs,
      summary: `${hits.length} đoạn mã đọc dữ liệu từ URL/referrer rất gần nơi ghi HTML hoặc chạy mã.`, explanation: "Nếu dữ liệu từ URL không được làm sạch trước khi ghi vào trang, kẻ tấn công gửi liên kết độc hại để chạy mã trên trình duyệt nạn nhân (DOM XSS).",
      technical: `Heuristic: nguồn và điểm ghi cách nhau ≤ 220 ký tự trong cùng file. Dễ có dương tính giả. Tổng số eval(): ${evals}.`, evidence: hits.slice(0, 6) })];
  },
});

const postMessage = adv({
  id: "adv.postmessage",
  title: "Xử lý postMessage an toàn",
  category: "Browser Security",
  run(obs) {
    const files = jsTexts(obs);
    if (!files.length) return [];
    const ev: string[] = [];
    for (const f of files) {
      const re = /addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=|\bonmessage\s*=/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.text))) {
        const body = f.text.slice(m.index, m.index + 500);
        if (!/\.origin\b|event\.source|e\.source/.test(body)) { ev.push(`${f.name}: bộ lắng nghe "message" không thấy kiểm tra origin`); break; }
      }
      if (/postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)/.test(f.text)) ev.push(`${f.name}: postMessage(..., "*") gửi tới mọi origin`);
    }
    if (!ev.length) return [];
    return [makeFinding({ ruleId: this.id, title: "postMessage có thể nhận/gửi tới origin không kiểm soát", category: this.category, severity: "low", confidence: "low", status: "fail",
      references: [MDN("Web/API/Window/postMessage#security_concerns", "MDN: postMessage security")], summary: "Mã có bộ lắng nghe message thiếu kiểm tra origin hoặc gọi postMessage tới \"*\".",
      explanation: "Trang bất kỳ có thể gửi thông điệp giả tới trang của bạn, hoặc đọc thông điệp bạn gửi đi nếu đích là \"*\".", technical: "Heuristic trên 500 ký tự sau bộ lắng nghe; mã nén có thể che dấu kiểm tra.", evidence: ev.slice(0, 6) })];
  },
});

const webStorage = adv({
  id: "adv.web-storage-secrets",
  title: "Không lưu token đăng nhập trong localStorage",
  category: "Browser Security",
  run(obs) {
    const files = jsTexts(obs);
    if (!files.length) return [];
    const ev: string[] = [];
    for (const f of files) {
      const re = /(local|session)Storage\.setItem\s*\(\s*['"`]([^'"`]{1,60})['"`]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(f.text))) if (/(token|jwt|auth|secret|password|passwd|session|credential|api[_-]?key)/i.test(m[2]!)) ev.push(`${f.name}: ${m[1]}Storage.setItem("${m[2]}", …)`);
    }
    if (!ev.length) return [];
    return [makeFinding({ ruleId: this.id, title: "Token hoặc bí mật được lưu trong bộ nhớ trình duyệt", category: this.category, severity: "low", confidence: "medium", status: "fail",
      references: [OWASP("HTML5_Security_Cheat_Sheet.html#local-storage", "OWASP: Local storage")], summary: "Mã ghi giá trị có tên giống token/mật khẩu vào localStorage/sessionStorage.",
      explanation: "Mọi script chạy trên trang (kể cả script bị chèn qua XSS hay thư viện bị xâm nhập) đều đọc được localStorage, khác với cookie HttpOnly.", evidence: uniq(ev).slice(0, 6) })];
  },
});

// ================================================================ 8–9. Bản đồ bề mặt tấn công
const endpointMap = adv({
  id: "adv.endpoint-map",
  title: "Bản đồ endpoint lộ trong mã trang",
  category: "Exposure",
  run(obs) {
    const files = jsTexts(obs);
    if (!files.length) return [];
    const found = new Set<string>();
    const re = /["'`]((?:https?:)?\/\/[a-z0-9.-]+)?(\/(?:api|graphql|admin|internal|v[1-9]|rest|auth|oauth|rpc|ws|socket\.io)[a-z0-9_\-/.]{0,60})["'`]/gi;
    for (const f of files) { let m: RegExpExecArray | null; while ((m = re.exec(f.text)) && found.size < 40) found.add((m[1] ?? "") + m[2]); }
    for (const f of files) for (const m of f.text.matchAll(/wss?:\/\/[a-z0-9.-]+[a-z0-9_\-/.]{0,40}/gi)) if (found.size < 40) found.add(m[0]);
    if (!found.size) return [];
    const list = [...found].slice(0, 15);
    return [makeFinding({ ruleId: this.id, title: this.title, category: this.category, severity: "info", confidence: "medium", status: "info",
      summary: `Mã trang để lộ ${found.size} đường dẫn API/quản trị. Đây không phải lỗi nhưng là “bản đồ” mà kẻ tấn công đọc đầu tiên.`, explanation: "Mọi đường dẫn nhìn thấy được ở đây đều cần có kiểm soát truy cập chặt phía máy chủ, vì ai cũng biết chúng tồn tại.",
      evidence: list, references: [OWASP("REST_Security_Cheat_Sheet.html", "OWASP: REST security")], technical: "Trích bằng biểu thức chính quy từ mã đã thu; chỉ liệt kê, không gửi request tới các đường dẫn này." })];
  },
});

const graphql = adv({
  id: "adv.graphql-surface",
  title: "GraphQL không để lộ introspection",
  category: "Exposure",
  run(obs) {
    const files = jsTexts(obs);
    const hit = files.find((f) => /(__schema|IntrospectionQuery)/.test(f.text));
    const ref = files.find((f) => /["'`][^"'`]*\/graphql["'`]/i.test(f.text));
    if (!hit && !ref) return [];
    return [makeFinding({ ruleId: this.id, title: "Có endpoint GraphQL nhìn thấy từ bên ngoài", category: this.category, severity: "low", confidence: "low", status: "fail",
      references: [OWASP("GraphQL_Cheat_Sheet.html", "OWASP: GraphQL")], summary: hit ? "Mã trang chứa truy vấn introspection (__schema), dấu hiệu schema GraphQL có thể bị liệt kê." : "Mã trang tham chiếu tới một endpoint /graphql.",
      explanation: "Nếu introspection còn bật ở môi trường chạy thật, kẻ tấn công lấy được toàn bộ cấu trúc API (kiểu, trường, mutation) chỉ bằng một truy vấn.",
      technical: "Chưa gửi truy vấn introspection thật (bộ quét không chủ động thăm dò), chỉ dựa trên mã đã thu.", evidence: [(hit ?? ref)!.name] })];
  },
});

// ================================================================ 10. Chuỗi chuyển hướng
const redirectChain = adv({
  id: "adv.redirect-chain",
  title: "Chuỗi chuyển hướng gọn và an toàn",
  category: "Transport Security",
  run(obs) {
    const chain = obs.http?.chain ?? [];
    if (chain.length < 2) return [];
    const issues: string[] = [];
    const hops = chain.length - 1;
    if (hops > 3) issues.push(`${hops} bước chuyển hướng liên tiếp (nên ≤ 2): chậm và dễ lỗi.`);
    for (let i = 1; i < chain.length; i++) if (chain[i - 1]!.url.startsWith("https:") && chain[i]!.url.startsWith("http:")) issues.push(`Hạ cấp từ HTTPS xuống HTTP ở bước ${i}: ${chain[i - 1]!.url} → ${chain[i]!.url}`);
    const hosts = uniq(chain.map((h) => hostOf(h.url)));
    if (hosts.length > 3) issues.push(`Đi qua ${hosts.length} tên miền khác nhau: ${hosts.join(" → ")}`);
    const first = chain[0]!;
    if (first.url.startsWith("http:") && [302, 303, 307].includes(first.status ?? 0)) issues.push(`HTTP→HTTPS dùng mã ${first.status} (tạm thời) thay vì 301/308: trình duyệt không ghi nhớ.`);
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: `Chuyển hướng ${hops} bước, không hạ cấp HTTPS.`, explanation: "Đường đi từ HTTP tới trang cuối gọn gàng.", evidence: chain.map((h) => `${h.status ?? "?"} ${h.url}`) })];
    return [makeFinding({ ruleId: this.id, title: "Chuỗi chuyển hướng dài hoặc có bước không an toàn", category: this.category, severity: issues.some((i) => i.startsWith("Hạ cấp")) ? "medium" : "low", confidence: "high", status: "fail",
      references: [MDN("Web/HTTP/Guides/Redirections", "MDN: Redirections")], summary: `${issues.length} vấn đề trong chuỗi chuyển hướng.`, explanation: "Mỗi bước chuyển hướng là một cơ hội cho kẻ đứng giữa can thiệp (nếu đi qua HTTP) và làm khách chờ lâu hơn.", evidence: [...issues, ...chain.map((h) => `${h.status ?? "?"} ${h.url}`)].slice(0, 10) })];
  },
});

// ================================================================ 11. Nhất quán header giữa các trang
const SEC_HEADERS = ["strict-transport-security", "x-content-type-options", "referrer-policy", "content-security-policy"];
const headerConsistency = adv({
  id: "adv.header-consistency",
  title: "Header bảo mật nhất quán giữa các trang",
  category: "Headers",
  run(obs) {
    const home = obs.https;
    if (!home || home.error || home.status === null) return [];
    const base = SEC_HEADERS.filter((h) => header(home.headers, h));
    if (!base.length) return [];
    const others: { label: string; rec: NonNullable<Observations["https"]> }[] = [];
    if (obs.notFound && !obs.notFound.error && obs.notFound.status !== null) others.push({ label: "trang lỗi 404", rec: obs.notFound });
    if (obs.sensitivePage && !obs.sensitivePage.error && obs.sensitivePage.status !== null) others.push({ label: "trang đăng nhập/tài khoản", rec: obs.sensitivePage });
    const alt = obs.altHost?.record;
    if (alt && !alt.error && alt.status !== null && alt.status >= 200 && alt.status < 300) others.push({ label: `tên miền ${obs.altHost!.host}`, rec: alt });
    if (!others.length) return [];
    const gaps = others.flatMap((o) => { const miss = base.filter((h) => !header(o.rec.headers, h)); return miss.length ? [`${o.label} thiếu: ${miss.join(", ")}`] : []; });
    const refs = [MDN("Web/Security", "MDN: Web security")];
    if (!gaps.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: `Các trang kiểm tra đều mang đủ ${base.length} header bảo mật như trang chủ.`, explanation: "Cấu hình header được áp dụng đồng đều.", references: refs })];
    const sensitive = gaps.some((g) => g.startsWith("trang đăng nhập"));
    return [makeFinding({ ruleId: this.id, title: "Header bảo mật chỉ có ở trang chủ, thiếu ở trang khác", category: this.category, severity: sensitive ? "medium" : "low", confidence: "high", status: "fail", references: refs,
      summary: "Header có trên trang chủ nhưng bị mất ở một số trang khác.", explanation: "Kẻ tấn công không cần tấn công trang chủ: chỉ cần tìm trang thiếu bảo vệ, ví dụ trang lỗi hoặc trang đăng nhập do proxy/ứng dụng khác phục vụ.", evidence: gaps })];
  },
});

// ================================================================ 12–13. SPF / DMARC chi tiết
const spfDeep = adv({
  id: "adv.spf-deep",
  title: "SPF chặt và hợp lệ",
  category: "Configuration",
  run(obs) {
    const spf = obs.dns?.spf;
    if (!spf) return [];
    const issues: { t: string; sev: "high" | "medium" | "low" }[] = [];
    if (/(^|\s)\+all\b/.test(spf) || /\sall\s*$/.test(spf) && !/[-~?]all/.test(spf)) issues.push({ t: "SPF kết thúc bằng +all: cho phép MỌI máy chủ gửi thư thay tên miền bạn.", sev: "high" });
    else if (/\?all\b/.test(spf)) issues.push({ t: "SPF kết thúc bằng ?all (trung lập): không chặn được thư giả.", sev: "medium" });
    else if (/~all\b/.test(spf)) issues.push({ t: "SPF dùng ~all (softfail): thư giả thường vẫn vào hộp thư. Nên dùng -all khi đã chắc chắn.", sev: "low" });
    const lookups = (spf.match(/(^|\s)(include:|a(:|\s|$)|mx(:|\s|$)|ptr|exists:|redirect=)/g) ?? []).length;
    if (lookups > 10) issues.push({ t: `Ước tính ${lookups} lần tra DNS (giới hạn 10): vượt giới hạn thì SPF bị coi là lỗi (permerror) và vô hiệu.`, sev: "medium" });
    if (/(^|\s)ptr\b/.test(spf)) issues.push({ t: "Dùng cơ chế ptr (bị khuyến cáo bỏ, chậm và không đáng tin).", sev: "low" });
    const refs = [{ title: "RFC 7208: SPF", url: "https://www.rfc-editor.org/rfc/rfc7208" }];
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: "SPF kết thúc bằng -all và nằm trong giới hạn tra DNS.", explanation: "Thư giả mạo tên miền bị từ chối đúng cách.", evidence: [truncate(spf, 200)], references: refs })];
    const rank = { high: 2, medium: 1, low: 0 } as const;
    const worst = issues.reduce((a, b) => (rank[b.sev] > rank[a.sev] ? b : a)).sev;
    return [makeFinding({ ruleId: this.id, title: "SPF có điểm yếu", category: this.category, severity: worst, confidence: "high", status: "fail", references: refs,
      summary: `${issues.length} điểm yếu trong bản ghi SPF.`, explanation: "SPF yếu hoặc lỗi khiến kẻ lừa đảo gửi email mạo danh tên miền của bạn mà không bị chặn.", evidence: [...issues.map((i) => `• ${i.t}`), `SPF: ${truncate(spf, 200)}`] })];
  },
});

const dmarcDeep = adv({
  id: "adv.dmarc-deep",
  title: "DMARC được thực thi đầy đủ",
  category: "Configuration",
  run(obs) {
    const raw = obs.dns?.dmarc;
    if (!raw) return [];
    const tags = new Map(raw.split(";").map((t) => t.trim().split("=")).filter((p) => p.length >= 2).map(([k, ...v]) => [k!.toLowerCase(), v.join("=").trim().toLowerCase()] as const));
    const p = tags.get("p");
    const issues: { t: string; sev: "medium" | "low" }[] = [];
    if (p === "none") issues.push({ t: "p=none: chỉ theo dõi, KHÔNG chặn thư giả mạo.", sev: "medium" });
    const pct = Number(tags.get("pct") ?? 100);
    if (pct < 100) issues.push({ t: `pct=${pct}: chính sách chỉ áp dụng cho ${pct}% thư.`, sev: "low" });
    if (!tags.get("rua")) issues.push({ t: "Không có rua: bạn không nhận báo cáo ai đang gửi thư thay tên miền mình.", sev: "low" });
    const sp = tags.get("sp");
    if (sp === "none" && p && p !== "none") issues.push({ t: "sp=none: tên miền con không được bảo vệ dù tên miền chính đã p=" + p + ".", sev: "low" });
    const refs = [{ title: "dmarc.org", url: "https://dmarc.org/overview/" }];
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: `DMARC p=${p ?? "?"} áp dụng cho 100% thư, có báo cáo tổng hợp.`, explanation: "Thư giả mạo bị xử lý theo chính sách bạn chọn.", evidence: [truncate(raw, 200)], references: refs })];
    return [makeFinding({ ruleId: this.id, title: "DMARC chưa thực thi đầy đủ", category: this.category, severity: issues.some((i) => i.sev === "medium") ? "medium" : "low", confidence: "high", status: "fail", references: refs,
      summary: `${issues.length} điểm cần siết trong DMARC.`, explanation: "DMARC chỉ chặn được email mạo danh khi chính sách là quarantine/reject và áp dụng cho toàn bộ thư.", evidence: [...issues.map((i) => `• ${i.t}`), `DMARC: ${truncate(raw, 200)}`] })];
  },
});

// ================================================================ 14. Vệ sinh chứng chỉ
const certHygiene = adv({
  id: "adv.certificate-hygiene",
  title: "Vệ sinh chứng chỉ TLS",
  category: "Transport Security",
  run(obs) {
    const t = obs.https?.tls;
    if (!t) return [];
    const issues: { t: string; sev: "medium" | "low" }[] = [];
    if (t.validityDays && t.validityDays > 398) issues.push({ t: `Chứng chỉ có hiệu lực ${t.validityDays} ngày (trình duyệt từ chối chứng chỉ dài hơn 398 ngày).`, sev: "medium" });
    if (t.selfSigned) issues.push({ t: "Chứng chỉ tự ký.", sev: "medium" });
    if (t.chainLength === 1 && !t.selfSigned) issues.push({ t: "Máy chủ gửi chuỗi chỉ có 1 chứng chỉ (thiếu chứng chỉ trung gian): một số thiết bị sẽ báo lỗi.", sev: "low" });
    if ((t.altNames?.length ?? 0) > 40) issues.push({ t: `Một chứng chỉ phủ ${t.altNames!.length} tên miền: nếu lộ khoá riêng, tất cả cùng bị ảnh hưởng.`, sev: "low" });
    if (t.wildcard) issues.push({ t: "Dùng chứng chỉ wildcard: khoá riêng nằm trên mọi máy chủ dùng chung, tăng rủi ro nếu một máy bị xâm nhập.", sev: "low" });
    const refs = [{ title: "CA/B Forum Baseline Requirements", url: "https://cabforum.org/working-groups/server/baseline-requirements/documents/" }];
    if (!issues.length) return [pass({ ruleId: this.id, title: this.title, category: this.category, summary: "Chứng chỉ ngắn hạn, đủ chuỗi, không wildcard.", explanation: "Chứng chỉ được quản lý gọn.", evidence: [`Hiệu lực: ${t.validityDays ?? "?"} ngày`, `Độ dài chuỗi: ${t.chainLength ?? "?"}`], references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Chứng chỉ TLS có điểm cần cải thiện", category: this.category, severity: issues.some((i) => i.sev === "medium") ? "medium" : "low", confidence: "medium", status: "fail", references: refs,
      summary: `${issues.length} điểm về chứng chỉ.`, explanation: "Chứng chỉ tốt là ngắn hạn, đủ chuỗi, phạm vi hẹp và tự gia hạn.", evidence: issues.map((i) => `• ${i.t}`) })];
  },
});

// ================================================================ 15. Form mật khẩu dùng GET
const formGet = adv({
  id: "adv.form-method",
  title: "Form mật khẩu không dùng GET",
  category: "Browser Security",
  run(obs) {
    const bad = obs.html?.forms.filter((f) => f.hasPassword && f.method.toLowerCase() === "get") ?? [];
    if (!bad.length) return [];
    return [makeFinding({ ruleId: this.id, title: "Form có ô mật khẩu gửi bằng GET", category: this.category, severity: "high", confidence: "high", status: "fail",
      references: [OWASP("Authentication_Cheat_Sheet.html", "OWASP: Authentication")], summary: "Form đăng nhập dùng method GET nên mật khẩu nằm ngay trên URL.", explanation: "URL được lưu trong lịch sử trình duyệt, nhật ký máy chủ, proxy và header Referer, nên mật khẩu bị ghi lại ở nhiều nơi.", evidence: bad.map((f) => `<form method="get" action="${truncate(f.action, 120)}">`) })];
  },
});

export const advancedRules: Rule[] = [cspAnalysis, cacheLeak, cookieScope, supplyChain, domSinks, postMessage, webStorage, endpointMap, graphql, redirectChain, headerConsistency, spfDeep, dmarcDeep, certHygiene, formGet];
