import { headerFix, RECOMMENDED } from "../remediation";
import type { Finding, Observations, Rule, Severity } from "../types";
import { header, headerEvidence, isHtml, livePage, makeFinding, MDN, OWASP, pass, truncate } from "../util";

const CAT = "Headers" as const;

export interface Csp {
  directives: Map<string, string[]>;
}

export function parseCsp(value: string): Csp {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1)); // theo chuẩn: lần xuất hiện đầu tiên được dùng
  }
  return { directives };
}

/** Nguồn script hiệu lực: script-src, nếu không có thì dùng default-src. */
function scriptSources(csp: Csp): string[] | null {
  return csp.directives.get("script-src") ?? csp.directives.get("default-src") ?? null;
}

/** Các host công cộng thường bị lợi dụng để vượt qua CSP (JSONP, thư viện Angular, v.v.). */
const BYPASS_HOSTS = /(^|\.)(ajax\.googleapis\.com|googleapis\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|accounts\.google\.com|[\w-]+\.cloudfront\.net|[\w-]+\.amazonaws\.com|[\w-]+\.herokuapp\.com|[\w-]+\.appspot\.com)$/i;

const csp: Rule = {
  id: "headers.csp",
  title: "Content-Security-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const url = p.finalUrl;
    const refs = [MDN("Web/HTTP/Guides/CSP", "MDN: Content Security Policy"), OWASP("Content_Security_Policy_Cheat_Sheet.html", "OWASP CSP Cheat Sheet")];
    const enforced = header(p.headers, "content-security-policy");
    const reportOnly = header(p.headers, "content-security-policy-report-only");
    const meta = obs.html?.metaCsp ?? null;
    const policyText = enforced ?? meta;

    if (!policyText) {
      return [makeFinding({
        ruleId: this.id, title: reportOnly ? "CSP chỉ ở chế độ báo cáo (chưa được áp dụng)" : "Thiếu Content-Security-Policy", category: CAT,
        severity: reportOnly ? "low" : "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: reportOnly ? "Đã khai báo Content-Security-Policy ở chế độ chỉ báo cáo: trình duyệt ghi nhận vi phạm nhưng không chặn gì cả." : "Website không giới hạn nguồn script và tài nguyên mà trình duyệt được phép tải.",
        explanation: "CSP là lớp phòng thủ thứ hai tốt nhất chống XSS (chèn mã độc vào trang): nếu kẻ tấn công chèn được một đoạn script, trình duyệt sẽ từ chối chạy nó.",
        technical: reportOnly ? "Chỉ có Content-Security-Policy-Report-Only." : "Không có header Content-Security-Policy và không có thẻ meta tương ứng.",
        evidence: [headerEvidence(p.headers, "content-security-policy"), ...(reportOnly ? [`Content-Security-Policy-Report-Only: ${truncate(reportOnly, 200)}`] : [])],
        remediation: headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Bắt đầu bằng chính sách chặt, thử nghiệm kỹ rồi chỉ nới những gì website thực sự cần. Nếu chưa chắc, hãy triển khai ở chế độ Report-Only trước."),
      })];
    }

    const parsed = parseCsp(policyText);
    const issues: { sev: Severity; text: string }[] = [];
    const scripts = scriptSources(parsed);
    if (scripts === null) {
      issues.push({ sev: "medium", text: "Không có script-src hoặc default-src: script không bị hạn chế." });
    } else {
      const hasNonceOrHash = scripts.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
      const strictDynamic = scripts.includes("'strict-dynamic'");
      if (scripts.includes("'unsafe-inline'") && !hasNonceOrHash && !strictDynamic) issues.push({ sev: "medium", text: "script-src cho phép 'unsafe-inline', làm mất gần hết tác dụng chống XSS." });
      if (scripts.includes("'unsafe-eval'")) issues.push({ sev: "low", text: "script-src cho phép 'unsafe-eval'." });
      if (scripts.some((s) => s === "*" || s === "https:" || s === "http:") && !strictDynamic) issues.push({ sev: "medium", text: "script-src cho phép script từ mọi host (ký tự * hoặc chỉ ghi giao thức)." });
      if (scripts.some((s) => s === "data:" || s === "blob:")) issues.push({ sev: "medium", text: "script-src cho phép nguồn data:/blob:, kẻ tấn công có thể dùng để chạy mã tuỳ ý." });
      const bypass = scripts.map((s) => s.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^\*\./, "")).filter((h) => BYPASS_HOSTS.test(h));
      if (bypass.length && !strictDynamic) issues.push({ sev: "low", text: `script-src tin cậy các host công cộng có thể bị lợi dụng để vượt CSP (${[...new Set(bypass)].slice(0, 3).join(", ")}).` });
    }
    const hasDefaultNone = parsed.directives.get("default-src")?.includes("'none'");
    if (!parsed.directives.has("object-src") && !hasDefaultNone && !(parsed.directives.get("default-src")?.includes("'self'"))) issues.push({ sev: "info", text: "Chưa hạn chế object-src (nên đặt object-src 'none')." });
    if (!parsed.directives.has("base-uri")) issues.push({ sev: "info", text: "Chưa đặt base-uri." });
    if ((obs.html?.forms.length ?? 0) > 0 && !parsed.directives.has("form-action")) issues.push({ sev: "info", text: "Trang có form nhưng chưa đặt form-action (nên giới hạn nơi form được gửi tới)." });
    if (!enforced && meta) issues.push({ sev: "info", text: "Chính sách đặt qua thẻ <meta> không dùng được frame-ancestors/report-uri; nên dùng HTTP header." });

    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    const worst = issues.reduce<Severity | null>((w, i) => (w === null || order.indexOf(i.sev) < order.indexOf(w) ? i.sev : w), null);
    const evidence = [`Content-Security-Policy: ${truncate(policyText, 400)}`];
    if (!worst || worst === "info") {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Content-Security-Policy được áp dụng và không chứa nguồn rõ ràng nguy hiểm.", explanation: "Script bị chèn vào trang khó có thể chạy hơn nhiều.", evidence: [...evidence, ...issues.map((i) => i.text)], references: refs })];
    }
    return [makeFinding({
      ruleId: this.id, title: "Content-Security-Policy còn yếu", category: CAT, severity: worst, confidence: "high", status: "fail", affectedUrl: url, references: refs,
      summary: issues.filter((i) => i.sev !== "info").map((i) => i.text).join(" "),
      explanation: "CSP cho phép script inline hoặc mọi host cho mức bảo vệ chống XSS thấp hơn nhiều so với vẻ ngoài của nó.",
      technical: issues.map((i) => `[${i.sev}] ${i.text}`).join("\n"), evidence,
      remediation: { ...headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Bỏ 'unsafe-inline'/'unsafe-eval' và các nguồn wildcard; dùng nonce hoặc hash cho script inline.") },
    })];
  },
};

const frameProtection: Rule = {
  id: "headers.frame-protection",
  title: "Chống clickjacking (X-Frame-Options / frame-ancestors)",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const xfo = header(p.headers, "x-frame-options")?.trim().toUpperCase();
    const fa = parseCsp(header(p.headers, "content-security-policy") ?? "").directives.get("frame-ancestors");
    const refs = [MDN("Web/HTTP/Reference/Headers/X-Frame-Options", "MDN: X-Frame-Options"), OWASP("Clickjacking_Defense_Cheat_Sheet.html", "OWASP Clickjacking Defense")];
    if (fa || xfo === "DENY" || xfo === "SAMEORIGIN") {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Website khác không thể nhúng trang này vào khung (frame).", explanation: "Chặn tấn công clickjacking (khung vô hình đánh lừa người dùng bấm nút).", evidence: [headerEvidence(p.headers, "x-frame-options"), `frame-ancestors: ${fa?.join(" ") ?? "(chưa đặt)"}`], references: refs })];
    }
    if (xfo) return []; // giá trị không hợp lệ → headers.broken
    const sensitive = obs.html?.hasPasswordInput === true;
    return [makeFinding({
      ruleId: this.id, title: "Trang có thể bị nhúng vào website khác (clickjacking)", category: CAT, severity: sensitive ? "medium" : "low", confidence: sensitive ? "medium" : "high", status: "fail",
      affectedUrl: p.finalUrl, references: refs,
      summary: "Không có X-Frame-Options lẫn directive frame-ancestors trong CSP.",
      explanation: "Một website độc hại có thể nhúng trang của bạn vào khung vô hình rồi đánh lừa khách bấm vào các nút trên đó (ví dụ “Xoá tài khoản”).",
      technical: "Không có header X-Frame-Options và không có frame-ancestors trong Content-Security-Policy.",
      evidence: [headerEvidence(p.headers, "x-frame-options"), headerEvidence(p.headers, "content-security-policy")],
      remediation: headerFix("X-Frame-Options", RECOMMENDED.xfo, obs.platforms, "Gửi X-Frame-Options: DENY (hoặc SAMEORIGIN), hoặc dùng cách hiện đại tương đương: CSP frame-ancestors 'none'."),
    })];
  },
};

const xcto: Rule = {
  id: "headers.x-content-type-options",
  title: "X-Content-Type-Options",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const v = header(p.headers, "x-content-type-options")?.trim().toLowerCase();
    const refs = [MDN("Web/HTTP/Reference/Headers/X-Content-Type-Options", "MDN: X-Content-Type-Options")];
    if (v === "nosniff") return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Trình duyệt được yêu cầu không tự đoán loại nội dung.", explanation: "Ngăn file người dùng tải lên bị hiểu nhầm thành script.", evidence: [headerEvidence(p.headers, "x-content-type-options")], references: refs })];
    if (v) return []; // sai giá trị → headers.broken
    return [makeFinding({
      ruleId: this.id, title: "Thiếu X-Content-Type-Options", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
      summary: "Chưa đặt header nosniff.", explanation: "Không có nó, trình duyệt có thể tự đoán loại file và đôi khi chạy nội dung do người dùng tải lên như một script.",
      evidence: [headerEvidence(p.headers, "x-content-type-options")], remediation: headerFix("X-Content-Type-Options", RECOMMENDED.xcto, obs.platforms),
    })];
  },
};

const crossOrigin: Rule = {
  id: "headers.cross-origin-isolation",
  title: "Cô lập tiến trình cross-origin (COOP / CORP / COEP)",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const wanted: [string, string][] = [["cross-origin-opener-policy", "same-origin"], ["cross-origin-resource-policy", "same-origin"], ["cross-origin-embedder-policy", "require-corp"]];
    const missing = wanted.filter(([n]) => !header(p.headers, n));
    const refs = [MDN("Web/HTTP/Guides/Cross-Origin_Opener_Policy", "MDN: Cross-Origin-Opener-Policy"), { title: "web.dev: Cross-origin isolation", url: "https://web.dev/articles/cross-origin-isolation-guide" }];
    if (missing.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Trang đã bật đầy đủ COOP, CORP và COEP.", explanation: "Trang được tách riêng khỏi các website khác trong trình duyệt, giảm nguy cơ rò rỉ dữ liệu kiểu Spectre.", evidence: wanted.map(([n]) => headerEvidence(p.headers, n)), references: refs })];
    return [makeFinding({
      ruleId: this.id, title: "Chưa bật các header cô lập cross-origin", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: p.finalUrl, references: refs,
      summary: `Thiếu: ${missing.map(([n]) => n).join(", ")}.`,
      explanation: "Đây là lớp tăng cường tuỳ chọn: chúng giúp tách riêng trang khỏi các website khác để hạn chế rò rỉ dữ liệu qua cửa sổ mở ra (popup) hoặc tài nguyên nhúng. Chỉ nên bật khi đã thử nghiệm vì có thể làm hỏng nội dung nhúng bên thứ ba.",
      evidence: wanted.map(([n]) => headerEvidence(p.headers, n)),
      remediation: headerFix("Cross-Origin-Opener-Policy", "same-origin", obs.platforms, "Bắt đầu với Cross-Origin-Opener-Policy: same-origin, sau đó cân nhắc CORP/COEP nếu cần cô lập hoàn toàn."),
    })];
  },
};

const charset: Rule = {
  id: "headers.charset",
  title: "Khai báo bảng mã ký tự",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const fromHeader = /charset=/i.test(p.contentType);
    if (fromHeader || obs.html?.metaCharset) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Trang khai báo bảng mã ký tự rõ ràng.", explanation: "Trình duyệt không phải đoán bảng mã.", evidence: [`Content-Type: ${p.contentType}`, ...(obs.html?.metaCharset ? [`<meta charset="${obs.html.metaCharset}">`] : [])] })];
    return [makeFinding({
      ruleId: this.id, title: "Trang không khai báo bảng mã ký tự", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: p.finalUrl,
      references: [MDN("Web/HTTP/Reference/Headers/Content-Type", "MDN: Content-Type")],
      summary: "Cả header Content-Type lẫn thẻ <meta charset> đều không nêu bảng mã.",
      explanation: "Khi không khai báo, trình duyệt phải tự đoán bảng mã. Trong lịch sử, việc đoán sai (ví dụ UTF-7) từng bị lợi dụng để chèn mã XSS dù đã lọc đầu vào.",
      evidence: [`Content-Type: ${p.contentType}`],
      remediation: headerFix("Content-Type", "text/html; charset=utf-8", obs.platforms, "Gửi Content-Type: text/html; charset=utf-8 và thêm <meta charset=\"utf-8\"> làm dòng đầu trong <head>."),
    })];
  },
};

const REFERRER_TOKENS = new Set(["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"]);
const PERMISSION_DIRECTIVE = /^[a-z-]+=(\(.*\)|\*|self)$/i;

/** Phát hiện header sai cú pháp hoặc đã lỗi thời: có mặt nhưng không làm đúng việc tác giả định. */
const brokenHeaders: Rule = {
  id: "headers.broken",
  title: "Các header bảo mật viết đúng cú pháp",
  category: CAT,
  run(obs: Observations): Finding[] {
    const p = livePage(obs);
    if (!p) return [];
    const url = p.finalUrl;
    const out: Finding[] = [];
    const add = (key: string, title: string, severity: Severity, summary: string, evidence: string[], fix?: ReturnType<typeof headerFix>) =>
      out.push(makeFinding({ ruleId: this.id, key, title, category: CAT, severity, confidence: "high", status: "fail", affectedUrl: url, summary, explanation: "Header có giá trị không hợp lệ thường bị trình duyệt bỏ qua, nên lớp bảo vệ bạn nghĩ mình đang có thực ra không hoạt động.", evidence, remediation: fix ?? null, references: [MDN("Web/HTTP/Reference/Headers", "MDN: HTTP headers")] }));

    const xfo = header(p.headers, "x-frame-options");
    if (xfo && !["DENY", "SAMEORIGIN"].includes(xfo.trim().toUpperCase())) {
      add("xfo", "X-Frame-Options có giá trị không hợp lệ", "low", /allow-from/i.test(xfo) ? "ALLOW-FROM đã lỗi thời và bị trình duyệt hiện đại bỏ qua." : `"${truncate(xfo, 60)}" không phải giá trị hợp lệ của X-Frame-Options (hãy dùng DENY hoặc SAMEORIGIN).`, [headerEvidence(p.headers, "x-frame-options")], headerFix("X-Frame-Options", RECOMMENDED.xfo, obs.platforms, "Dùng DENY hoặc SAMEORIGIN, hoặc CSP frame-ancestors."));
    }
    const x = header(p.headers, "x-content-type-options");
    if (x && x.trim().toLowerCase() !== "nosniff") add("xcto", "X-Content-Type-Options có giá trị không hợp lệ", "low", `"${truncate(x, 60)}" không hợp lệ; giá trị duy nhất được chấp nhận là nosniff.`, [headerEvidence(p.headers, "x-content-type-options")], headerFix("X-Content-Type-Options", RECOMMENDED.xcto, obs.platforms));

    const hsts = header(obs.https && !obs.https.error ? obs.https.headers : undefined, "strict-transport-security");
    if (hsts) {
      const m = /max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
      if (!m) add("hsts-no-maxage", "Header HSTS thiếu max-age", "medium", "Strict-Transport-Security không có max-age sẽ bị trình duyệt bỏ qua.", [`Strict-Transport-Security: ${truncate(hsts, 200)}`], headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms));
      else if (Number(m[1]) === 0) add("hsts-zero", "HSTS bị tắt chủ động (max-age=0)", "medium", "max-age=0 yêu cầu trình duyệt quên quy tắc chỉ dùng HTTPS.", [`Strict-Transport-Security: ${truncate(hsts, 200)}`], headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms));
    }

    const cspH = header(p.headers, "content-security-policy");
    if (cspH) {
      const bareKeywords = /(?:^|[\s;])(self|none|unsafe-inline|unsafe-eval|strict-dynamic)(?=[\s;]|$)/i.exec(cspH.replace(/'[^']*'/g, ""));
      if (bareKeywords) add("csp-unquoted", "CSP dùng từ khoá thiếu dấu nháy đơn", "medium", `"${bareKeywords[1]}" phải viết trong dấu nháy đơn ('${bareKeywords[1]}'); không có dấu nháy, nó bị coi là tên host.`, [`Content-Security-Policy: ${truncate(cspH, 300)}`], headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms));
    }
    const meta = obs.html?.metaCsp;
    if (meta && !cspH && /frame-ancestors|report-uri|sandbox/i.test(meta)) add("csp-meta-ignored", "CSP trong <meta> chứa directive mà trình duyệt bỏ qua", "low", "frame-ancestors, report-uri và sandbox không có tác dụng khi CSP được đặt qua thẻ <meta>.", [`<meta CSP>: ${truncate(meta, 300)}`], headerFix("Content-Security-Policy", RECOMMENDED.csp, obs.platforms, "Hãy gửi chính sách qua HTTP header."));

    const rp = header(p.headers, "referrer-policy");
    if (rp) {
      const tokens = rp.split(",").map((t) => t.trim().toLowerCase());
      if (!tokens.some((t) => REFERRER_TOKENS.has(t))) add("referrer", "Referrer-Policy có giá trị không hợp lệ", "low", `"${truncate(rp, 60)}" không phải chính sách được nhận diện.`, [headerEvidence(p.headers, "referrer-policy")], headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms));
    }
    const pp = header(p.headers, "permissions-policy");
    if (pp) {
      const bad = pp.split(/,(?![^()]*\))/).map((s) => s.trim()).filter(Boolean).find((d) => !PERMISSION_DIRECTIVE.test(d));
      if (bad) add("permissions", "Permissions-Policy sai cú pháp", "low", `"${truncate(bad, 60)}" không đúng cú pháp Permissions-Policy (ví dụ: camera=(), geolocation=(self)).`, [headerEvidence(p.headers, "permissions-policy")], headerFix("Permissions-Policy", RECOMMENDED.permissions, obs.platforms));
    }
    const xss = header(p.headers, "x-xss-protection");
    if (xss && /^1/.test(xss.trim())) out.push(makeFinding({ ruleId: this.id, key: "xss-protection", title: "X-XSS-Protection đã lỗi thời đang được bật", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url, summary: "X-XSS-Protection: 1 dựa vào bộ lọc đã bị gỡ khỏi trình duyệt và có thể gây lỗ hổng ở trình duyệt đời cũ.", explanation: "Trình duyệt hiện đại bỏ qua nó. OWASP khuyên đặt giá trị 0 và dựa vào CSP.", evidence: [headerEvidence(p.headers, "x-xss-protection")], remediation: headerFix("X-XSS-Protection", "0", obs.platforms, "Đặt X-XSS-Protection: 0 (hoặc bỏ hẳn) và dùng Content-Security-Policy."), references: [OWASP("HTTP_Headers_Cheat_Sheet.html", "OWASP HTTP Headers")] }));

    if (out.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Không có header bảo mật nào sai cú pháp hoặc mâu thuẫn.", explanation: "Các header đang có đều có giá trị hợp lệ.", evidence: [] })];
    return out;
  },
};

export const headerRules: Rule[] = [csp, frameProtection, xcto, brokenHeaders, crossOrigin, charset];
