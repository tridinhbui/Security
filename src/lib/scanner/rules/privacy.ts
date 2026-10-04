import { getDomain } from "tldts";
import { headerFix, RECOMMENDED } from "../remediation";
import type { Observations, Rule } from "../types";
import { header, headerEvidence, isHtml, livePage, makeFinding, MDN, pass } from "../util";

const CAT = "Privacy" as const;

const referrerPolicy: Rule = {
  id: "privacy.referrer-policy",
  title: "Referrer-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const v = (header(p.headers, "referrer-policy") ?? obs.html?.metaReferrer ?? "").toLowerCase();
    const refs = [MDN("Web/HTTP/Reference/Headers/Referrer-Policy", "MDN: Referrer-Policy")];
    if (!v) {
      return [makeFinding({ ruleId: this.id, title: "Chưa đặt Referrer-Policy", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: "Không có header Referrer-Policy nào được gửi.", explanation: "Khi khách bấm liên kết sang website khác, trình duyệt có thể cho website đó biết khách đến từ trang nào của bạn — kể cả những URL chứa mã hay ID riêng tư. Trình duyệt hiện đại mặc định dùng chính sách an toàn, nhưng bản cũ thì không.",
        evidence: [headerEvidence(p.headers, "referrer-policy")], remediation: headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms) })];
    }
    if (/\b(unsafe-url|no-referrer-when-downgrade)\b/.test(v)) {
      return [makeFinding({ ruleId: this.id, title: "Referrer-Policy làm lộ URL đầy đủ", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Referrer-Policy "${v}" gửi URL đầy đủ của trang tới website khác.`, explanation: "URL đầy đủ (kèm đường dẫn và query string) được chia sẻ với mọi bên thứ ba mà bạn liên kết tới hoặc tải tài nguyên từ đó.",
        evidence: [headerEvidence(p.headers, "referrer-policy")], remediation: headerFix("Referrer-Policy", RECOMMENDED.referrer, obs.platforms) })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Đã đặt Referrer-Policy bảo vệ quyền riêng tư.", explanation: "Website khác biết rất ít về nơi khách đến.", evidence: [`Referrer-Policy: ${v}`], references: refs })];
  },
};

const permissionsPolicy: Rule = {
  id: "privacy.permissions-policy",
  title: "Permissions-Policy",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p || !isHtml(p.contentType)) return [];
    const v = header(p.headers, "permissions-policy");
    const refs = [MDN("Web/HTTP/Reference/Headers/Permissions-Policy", "MDN: Permissions-Policy")];
    if (v) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Các tính năng trình duyệt được giới hạn tường minh.", explanation: "Nội dung nhúng không thể lặng lẽ dùng camera, micro hay vị trí.", evidence: [headerEvidence(p.headers, "permissions-policy")], references: refs })];
    return [makeFinding({ ruleId: this.id, title: "Chưa đặt Permissions-Policy", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: p.finalUrl, references: refs,
      summary: "Website không giới hạn các tính năng mạnh của trình duyệt cho chính nó và nội dung nhúng.", explanation: "Tăng cường tuỳ chọn: ngăn script hoặc khung của bên thứ ba dùng camera, micro hay vị trí ngay cả khi chúng cố tình.",
      evidence: [headerEvidence(p.headers, "permissions-policy")], remediation: headerFix("Permissions-Policy", RECOMMENDED.permissions, obs.platforms) })];
  },
};

const thirdParties: Rule = {
  id: "privacy.third-party-origins",
  title: "Request tới bên thứ ba",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const self = getDomain(new URL(obs.page.finalUrl).hostname);
    const hosts = new Set<string>();
    for (const r of obs.html.resources) {
      try {
        const h = new URL(r.url).hostname;
        if (getDomain(h) !== self) hosts.add(h);
      } catch { /* bỏ qua */ }
    }
    if (hosts.size === 0) return [pass({ ruleId: this.id, title: "Trang không tải tài nguyên từ bên thứ ba", category: CAT, affectedUrl: obs.page.finalUrl, summary: "Trang tải mọi thứ từ chính tên miền của nó.", explanation: "Địa chỉ IP và hành vi duyệt web của khách không bị trang này chia sẻ cho công ty khác.", evidence: [] })];
    return [makeFinding({ ruleId: this.id, title: "Trang tải tài nguyên từ bên thứ ba", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `${hosts.size} host bên ngoài nhận được địa chỉ IP và thông tin trình duyệt của khách.`, explanation: "Mỗi script hay tài nguyên bên thứ ba là một vấn đề về quyền riêng tư (đồng ý, công bố) và một rủi ro chuỗi cung ứng. Chỉ giữ những gì thật cần.",
      technical: "Các host riêng biệt được tham chiếu bởi thẻ script/link/img/iframe/media trên trang (chỉ HTML trang chủ).", evidence: [...hosts].sort().slice(0, 20),
      remediation: { summary: "Xem lại danh sách, gỡ các tích hợp không cần, tự lưu trữ tài nguyên tĩnh và công bố phần còn lại trong chính sách quyền riêng tư.", snippets: [] } })];
  },
};

/** Bộ nhận diện trình theo dõi/quảng cáo phổ biến (host hoặc đoạn mã trong script). */
export const TRACKERS: { name: string; host?: RegExp; code?: RegExp }[] = [
  { name: "Google Analytics", host: /(^|\.)google-analytics\.com$/, code: /\bgtag\(|GoogleAnalyticsObject|_gaq\.push/ },
  { name: "Google Tag Manager", host: /(^|\.)googletagmanager\.com$/ },
  { name: "Google Ads / DoubleClick", host: /(^|\.)(doubleclick\.net|googleadservices\.com|googlesyndication\.com)$/ },
  { name: "Meta (Facebook) Pixel", host: /(^|\.)connect\.facebook\.net$/, code: /\bfbq\(/ },
  { name: "TikTok Pixel", host: /(^|\.)analytics\.tiktok\.com$/, code: /\bttq\.(load|track|page)/ },
  { name: "Hotjar", host: /(^|\.)hotjar\.com$/, code: /\bhj\(/ },
  { name: "Microsoft Clarity", host: /(^|\.)clarity\.ms$/, code: /\bclarity\(/ },
  { name: "LinkedIn Insight", host: /(^|\.)snap\.licdn\.com$/ },
  { name: "Zalo Pixel", host: /(^|\.)sp\.zalo\.me$/ },
  { name: "Mixpanel", host: /(^|\.)mixpanel\.com$/ },
  { name: "Segment", host: /(^|\.)segment\.(com|io)$/ },
  { name: "Intercom", host: /(^|\.)intercom(cdn)?\.(com|io)$/ },
];

export function detectTrackers(obs: Observations): string[] {
  const found = new Set<string>();
  for (const r of obs.html?.resources ?? []) {
    let h = "";
    try { h = new URL(r.url).hostname; } catch { continue; }
    for (const t of TRACKERS) if (t.host?.test(h)) found.add(t.name);
  }
  for (const s of obs.html?.scripts ?? []) {
    const text = s.content ?? s.fetched?.body ?? "";
    if (!text) continue;
    for (const t of TRACKERS) if (t.code?.test(text)) found.add(t.name);
  }
  return [...found].sort();
}

const trackers: Rule = {
  id: "privacy.trackers",
  title: "Trình theo dõi và quảng cáo bên thứ ba",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const t = detectTrackers(obs);
    const url = obs.page.finalUrl;
    if (t.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Không phát hiện trình theo dõi hay pixel quảng cáo phổ biến nào trên trang chủ.", explanation: "Hành vi của khách không bị gửi cho các nền tảng quảng cáo/phân tích lớn qua trang này.", evidence: [] })];
    return [makeFinding({
      ruleId: this.id, title: "Phát hiện trình theo dõi/quảng cáo bên thứ ba", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url,
      summary: `Trang chủ tải ${t.length} công cụ theo dõi: ${t.join(", ")}.`,
      explanation: "Các công cụ này thu thập hành vi của khách và thường đặt cookie. Nếu bạn xử lý dữ liệu cá nhân của người dùng tại Việt Nam, hãy xem Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân và các quy định liên quan: thường cần thông báo rõ mục đích và có cơ chế xin đồng ý. Đây không phải tư vấn pháp lý.",
      technical: "Nhận diện theo tên host của tài nguyên và đoạn mã khởi tạo đặc trưng (gtag(), fbq(), hj()…). Chỉ quan sát trang chủ, không chạy script.",
      evidence: t.map((x) => `• ${x}`),
      remediation: { summary: "Chỉ giữ công cụ thật sự cần, hiển thị banner xin đồng ý trước khi nạp trình theo dõi, và nêu rõ trong chính sách quyền riêng tư.", steps: ["Dùng cơ chế tải có điều kiện: chỉ nạp script theo dõi sau khi người dùng đồng ý (Google Consent Mode v2 nếu dùng Google).", "Ưu tiên giải pháp phân tích tôn trọng quyền riêng tư (tự lưu trữ, không cookie) khi có thể."], snippets: [] },
    })];
  },
};

export const privacyRules: Rule[] = [referrerPolicy, permissionsPolicy, thirdParties, trackers];
