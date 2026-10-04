import { cookieFix } from "../remediation";
import type { Finding, Observations, Rule, Severity } from "../types";
import { header, isHtml, livePage, makeFinding, MDN, pass, setCookies } from "../util";

const CAT = "Cookies & Sessions" as const;
const SESSION_NAME = /(sess|sid\b|^sid|auth|token|jwt|login|remember|identity|connect\.sid|next-auth|__session|sb-.*-auth)/i;
const CSRF_NAME = /csrf|xsrf/i;

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "lax" | "strict" | "none" | null;
  path: string | null;
  domain: string | null;
  maxAgeDays: number | null;
  /** Số ngày còn lại tới Expires (nếu có). */
  expiresInDays: number | null;
  source: string;
}

export function parseSetCookie(raw: string, source: string): ParsedCookie | null {
  const parts = raw.split(";").map((p) => p.trim());
  const eq = parts[0]!.indexOf("=");
  if (eq <= 0) return null;
  const c: ParsedCookie = { name: parts[0]!.slice(0, eq), secure: false, httpOnly: false, sameSite: null, path: null, domain: null, maxAgeDays: null, expiresInDays: null, source };
  for (const a of parts.slice(1)) {
    const [k, ...rest] = a.split("=");
    const key = k!.toLowerCase();
    const val = rest.join("=");
    if (key === "secure") c.secure = true;
    else if (key === "httponly") c.httpOnly = true;
    else if (key === "samesite") c.sameSite = (["lax", "strict", "none"].includes(val.toLowerCase()) ? val.toLowerCase() : null) as ParsedCookie["sameSite"];
    else if (key === "path") c.path = val;
    else if (key === "domain") c.domain = val;
    else if (key === "max-age" && /^\d+$/.test(val)) c.maxAgeDays = Number(val) / 86400;
    else if (key === "expires" && !Number.isNaN(Date.parse(val))) c.expiresInDays = (Date.parse(val) - Date.now()) / 86_400_000;
  }
  return c;
}

function collectCookies(obs: Observations): ParsedCookie[] {
  const seen = new Map<string, ParsedCookie>();
  const records = [obs.https, obs.sensitivePage, obs.page].filter((r): r is NonNullable<typeof r> => !!r);
  for (const r of records) {
    for (const hop of r.chain) {
      for (const raw of setCookies(hop.headers)) {
        const c = parseSetCookie(raw, hop.url);
        if (c) seen.set(c.name, c);
      }
    }
  }
  return [...seen.values()];
}

/** Bằng chứng đã che: chỉ ghi các cờ thuộc tính, không bao giờ ghi giá trị cookie. */
function cookieEvidence(c: ParsedCookie): string {
  return [`${c.name}=<đã che>`, c.secure ? "Secure" : "", c.httpOnly ? "HttpOnly" : "", c.sameSite ? `SameSite=${c.sameSite}` : "", c.path ? `Path=${c.path}` : "", c.domain ? `Domain=${c.domain}` : ""].filter(Boolean).join("; ");
}

const cookieFlags: Rule = {
  id: "cookies.flags",
  title: "Cookie dùng Secure, HttpOnly và SameSite",
  category: CAT,
  run(obs) {
    if (!obs.page) return [];
    const cookies = collectCookies(obs);
    const url = obs.page.finalUrl;
    const refs = [MDN("Web/HTTP/Guides/Cookies", "MDN: Using HTTP cookies"), MDN("Web/HTTP/Reference/Headers/Set-Cookie", "MDN: Set-Cookie")];
    if (cookies.length === 0) {
      return [pass({ ruleId: this.id, title: "Lần truy cập đầu không đặt cookie nào", category: CAT, affectedUrl: url, summary: "Website không đặt cookie nào khi có request ẩn danh.", explanation: "Không có gì để cấu hình sai — và không cần banner đồng ý cho cookie ngay lần tải đầu.", evidence: [] })];
    }
    const out: Finding[] = [];
    const secureSite = obs.pageIsHttps;
    for (const c of cookies) {
      const session = SESSION_NAME.test(c.name) && !CSRF_NAME.test(c.name);
      const problems: string[] = [];
      let sev: Severity = "info";
      const bump = (s: Severity) => { const order: Severity[] = ["critical", "high", "medium", "low", "info"]; if (order.indexOf(s) < order.indexOf(sev)) sev = s; };
      if (secureSite && !c.secure) { problems.push("Secure"); bump(session ? "medium" : "low"); }
      if (!c.httpOnly && !CSRF_NAME.test(c.name)) { problems.push("HttpOnly"); bump(session ? "medium" : "info"); }
      if (!c.sameSite) { problems.push("SameSite"); bump(session ? "low" : "info"); }
      const extra: string[] = [];
      if (c.sameSite === "none" && !c.secure) { extra.push("SameSite=None bắt buộc phải có Secure; trình duyệt sẽ từ chối cookie này"); bump("medium"); }
      if (c.name.startsWith("__Host-") && (!c.secure || c.path !== "/" || c.domain)) { extra.push("tiền tố __Host- yêu cầu Secure, Path=/ và không có Domain"); bump("low"); }
      if (c.name.startsWith("__Secure-") && !c.secure) { extra.push("tiền tố __Secure- yêu cầu Secure"); bump("low"); }
      const lifeDays = c.maxAgeDays ?? c.expiresInDays;
      if (session && lifeDays !== null && lifeDays > 30) { extra.push(`cookie phiên có thời hạn ${Math.round(lifeDays)} ngày (nên ngắn hơn, hoặc dùng cookie phiên không đặt hạn)`); bump("low"); }
      if (problems.length === 0 && extra.length === 0) continue;
      // Non-session cookies missing only HttpOnly/SameSite are not worth a failing finding.
      if (sev === "info") continue;
      out.push(makeFinding({
        ruleId: this.id, key: c.name, title: `Cookie "${c.name}" thiếu cờ bảo mật`, category: CAT, severity: sev,
        confidence: session ? "high" : "medium", status: "fail", affectedUrl: url, references: refs,
        summary: `${session ? "Đây có vẻ là cookie phiên/đăng nhập. " : ""}${[problems.length ? `Thiếu: ${problems.join(", ")}.` : "", ...extra.map((e) => e.charAt(0).toUpperCase() + e.slice(1) + ".")].filter(Boolean).join(" ")}`,
        explanation: "Thiếu Secure thì cookie có thể lộ qua HTTP thuần; thiếu HttpOnly thì script bị chèn vào có thể đánh cắp; thiếu SameSite thì website khác có thể kích hoạt request đã xác thực (CSRF).",
        technical: `Các cờ Set-Cookie quan sát được cho ${c.name} (đã che giá trị).`, evidence: [cookieEvidence(c)],
        remediation: cookieFix(obs.platforms, [...problems, ...(c.sameSite === "none" && !c.secure ? ["Secure"] : [])].filter((v, i, a) => a.indexOf(v) === i)),
      }));
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `${cookies.length} cookie được đặt với đầy đủ cờ phù hợp.`, explanation: "Cookie được bảo vệ khỏi bị chặn bắt, bị script đọc và bị dùng từ website khác.", evidence: cookies.slice(0, 6).map(cookieEvidence), references: refs })];
    }
    return out;
  },
};

const SENSITIVE_PATH = /(login|signin|sign-in|account|admin|dashboard|profile|checkout|settings|billing|wp-admin)/i;

const cacheControl: Rule = {
  id: "cookies.cache-control-sensitive",
  title: "Trang nhạy cảm không bị lưu đệm (cache)",
  category: CAT,
  run(obs) {
    const candidates = [livePage(obs), obs.sensitivePage].filter((r): r is NonNullable<typeof r> => !!r && !r.error && r.status === 200 && isHtml(r.contentType));
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const r of candidates) {
      if (seen.has(r.finalUrl)) continue;
      seen.add(r.finalUrl);
      const isHome = r === obs.page;
      const path = new URL(r.finalUrl).pathname;
      const hasCookies = setCookies(r.headers).length > 0;
      const hasLogin = isHome ? obs.html?.hasPasswordInput === true : /type=["']?password/i.test(r.body);
      const sensitive = SENSITIVE_PATH.test(path) || hasLogin || (hasCookies && setCookies(r.headers).some((c) => SESSION_NAME.test(c.split("=")[0]!)));
      if (!sensitive) continue;
      const cc = (header(r.headers, "cache-control") ?? "").toLowerCase();
      const protectedCache = /no-store|private/.test(cc);
      const evidence = [`Cache-Control: ${cc || "(không có)"}`, ...(header(r.headers, "pragma") ? [`Pragma: ${header(r.headers, "pragma")}`] : [])];
      if (protectedCache) {
        out.push(pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: r.finalUrl, summary: "Trang trông có vẻ nhạy cảm này yêu cầu các bộ nhớ đệm không lưu nó.", explanation: "Trang riêng tư sẽ không bị proxy dùng chung giữ lại hay hiện lại qua nút Back.", evidence }));
        continue;
      }
      const explicitPublic = /\bpublic\b|s-maxage|max-age=(?!0\b)\d+/.test(cc);
      out.push(makeFinding({
        ruleId: this.id, title: "Trang trông nhạy cảm có thể bị lưu đệm", category: CAT, severity: explicitPublic && hasCookies ? "medium" : "low", confidence: explicitPublic ? "medium" : "low", status: "fail",
        affectedUrl: r.finalUrl, references: [MDN("Web/HTTP/Guides/Caching", "MDN: HTTP caching")],
        summary: `Trang này trông giống trang đăng nhập/tài khoản (${hasLogin ? "có ô mật khẩu" : "URL hoặc cookie gợi ý như vậy"}) nhưng không gửi Cache-Control: no-store.`,
        explanation: "Bộ nhớ đệm dùng chung (CDN, proxy công ty) hoặc nút Back của trình duyệt có thể giữ nội dung cá nhân hoặc theo phiên và hiện cho nhầm người.",
        technical: "Heuristic: độ nhạy cảm được suy ra từ đường dẫn URL, ô mật khẩu và cookie giống phiên — hãy xác minh với các trang đã đăng nhập thật của bạn.", evidence,
        remediation: { summary: "Gửi Cache-Control: no-store (hoặc private, no-cache) trên các trang tài khoản và trang đã xác thực.", snippets: [] },
      }));
    }
    return out;
  },
};

export const cookieRules: Rule[] = [cookieFlags, cacheControl];
