import { detectPublicConfig, detectSecrets } from "../secrets";
import type { Finding, Observations, Rule, Severity } from "../types";
import { makeFinding, MDN, OWASP, pass, pathOf, truncate } from "../util";

const CAT = "Exposure" as const;

/** Mọi tài liệu văn bản công khai đã tải: HTML trang chủ, script inline, JS cùng origin. */
function publicDocuments(obs: Observations): { url: string; text: string }[] {
  const docs: { url: string; text: string }[] = [];
  if (obs.page?.body) docs.push({ url: obs.page.finalUrl, text: obs.page.body });
  for (const s of obs.scripts) {
    const text = s.content ?? s.fetched?.body;
    if (text) docs.push({ url: s.url ?? `${obs.page?.finalUrl ?? obs.target.url}#inline-script`, text });
  }
  return docs;
}

const secrets: Rule = {
  id: "exposure.secrets",
  title: "Không có bí mật hiển nhiên trong HTML/JavaScript công khai",
  category: CAT,
  run(obs) {
    const docs = publicDocuments(obs);
    if (docs.length === 0) return [];
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const d of docs) {
      for (const m of detectSecrets(d.text)) {
        const key = `${m.id}|${m.redacted}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const byDesign = m.publicByDesign === true;
        out.push(makeFinding({
          ruleId: this.id, key: `${m.id}:${pathOf(d.url)}:${m.redacted}`,
          title: byDesign ? `${m.label} xuất hiện trong mã công khai (vốn được thiết kế để công khai)` : `${m.label} bị lộ trong mã công khai`,
          category: CAT, severity: m.severity, confidence: m.confidence, status: byDesign ? "info" : "fail", affectedUrl: d.url,
          references: [{ title: "OWASP: Secrets Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" }],
          summary: byDesign ? `${m.label} xuất hiện trong một file công khai. ${m.note}` : `${m.label} có thể được đọc bởi bất kỳ ai xem mã nguồn trang hoặc tải file JavaScript.`,
          explanation: byDesign ? "Các định danh này được thiết kế để đưa xuống trình duyệt. Hãy đảm bảo chúng được giới hạn (theo referrer/tên miền hoặc bằng chính sách cơ sở dữ liệu)." : "Mọi thứ gửi xuống trình duyệt đều là công khai. Kẻ xấu quét web liên tục để tìm khoá bị lộ và lạm dụng chỉ trong vài phút.",
          technical: `${m.note} Nhận diện bằng mẫu riêng của từng nhà cung cấp; giá trị đầy đủ không được lưu.`,
          evidence: [`${m.label}: ${m.redacted}`, `Tìm thấy tại: ${truncate(d.url, 200)}`],
          remediation: byDesign
            ? { summary: "Giới hạn khoá và kiểm tra lại kiểm soát truy cập.", steps: m.id === "supabase-anon-key" ? ["Bật Row Level Security trên mọi bảng và viết policy tường minh.", "Không bao giờ đưa khoá service_role xuống trình duyệt."] : ["Trong Google Cloud Console, giới hạn khoá theo HTTP referrer và theo từng API được phép gọi."], snippets: [] }
            : { summary: "Coi thông tin xác thực này đã bị lộ: thu hồi ngay, cấp khoá mới và chỉ đặt ở phía máy chủ.", steps: ["Thu hồi/xoay khoá ngay trong trang quản trị của nhà cung cấp — chỉ xoá khỏi mã nguồn là chưa đủ.", "Chuyển giá trị sang biến môi trường phía máy chủ và gọi nhà cung cấp từ API route hoặc server action.", "Kiểm tra nhật ký của nhà cung cấp để tìm hoạt động lạ.", "Không bao giờ đặt tiền tố NEXT_PUBLIC_, VITE_, REACT_APP_… cho bí mật phía máy chủ — các biến đó bị đóng gói vào JS công khai."], snippets: [] },
        }));
      }
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, summary: `Không tìm thấy định dạng thông tin xác thực nào đã biết trong ${docs.length} tài liệu công khai.`, explanation: "So khớp mẫu thận trọng không thấy khoá API, khoá riêng hay chuỗi kết nối. Kiểm tra này không thể chứng minh là hoàn toàn không có.", evidence: [`Đã quét ${docs.length} tài liệu`], technical: "Chỉ dùng mẫu riêng của từng nhà cung cấp; cố ý không dùng heuristic kiểu “trông giống mật khẩu” để tránh báo sai.", affectedUrl: obs.page?.finalUrl ?? null })];
    }
    return out;
  },
};

const publicConfig: Rule = {
  id: "exposure.public-config",
  title: "Giá trị môi trường phía trình duyệt",
  category: CAT,
  run(obs) {
    const docs = publicDocuments(obs);
    const entries = new Map<string, { len: number; sensitive: boolean; url: string }>();
    for (const d of docs) for (const e of detectPublicConfig(d.text)) if (!entries.has(e.key)) entries.set(e.key, { len: e.valueLength, sensitive: e.sensitiveName, url: d.url });
    if (entries.size === 0) return [];
    const sensitive = [...entries.entries()].filter(([, v]) => v.sensitive);
    const out: Finding[] = [];
    if (sensitive.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "sensitive-names", title: "Cấu hình công khai chứa biến có tên giống bí mật", category: CAT, severity: "medium", confidence: "medium", status: "fail", affectedUrl: sensitive[0]![1].url,
        summary: `${sensitive.length} biến lúc build có tên kiểu SECRET/PRIVATE/PASSWORD đang được đóng gói vào JavaScript công khai.`,
        explanation: "Biến có tiền tố công khai (NEXT_PUBLIC_, VITE_, REACT_APP_…) được sao chép vào bundle trình duyệt cho mọi người. Tên nghe như bí mật cho thấy có thể một thứ riêng tư đã bị đưa ra nhầm.",
        technical: "Heuristic dựa trên tên biến; giá trị chỉ được đo độ dài, không bao giờ lưu.",
        evidence: sensitive.slice(0, 10).map(([k, v]) => `${k} = <đã che, ${v.len} ký tự>`),
        remediation: { summary: "Bỏ tiền tố công khai, giữ giá trị ở phía máy chủ, xoay khoá nếu nó là thật rồi build lại.", snippets: [] },
      }));
    }
    const rest = [...entries.keys()].filter((k) => !entries.get(k)!.sensitive);
    if (rest.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "list", title: "Giá trị môi trường được gửi xuống trình duyệt", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: entries.get(rest[0]!)!.url,
        summary: `${rest.length} giá trị cấu hình được nhúng trong JavaScript công khai.`,
        explanation: "Điều này bình thường với cấu hình công khai như URL API hay khoá publishable. Chỉ cần chắc chắn không có giá trị nào thực sự riêng tư.",
        evidence: rest.slice(0, 15).map((k) => `${k} = <đã che, ${entries.get(k)!.len} ký tự>`),
        remediation: { summary: "Rà soát danh sách này: thứ gì gây hại nếu người lạ nhìn thấy thì phải chuyển về phía máy chủ.", snippets: [] },
      }));
    }
    return out;
  },
};

const sourceMaps: Rule = {
  id: "exposure.source-maps",
  title: "Source map không công khai",
  category: CAT,
  run(obs) {
    if (obs.sourceMaps.length === 0) return [];
    const exposed = obs.sourceMaps.filter((s) => s.exposed);
    const refs = [MDN("Tools/Debugger/How_to/Use_a_source_map", "MDN: Source maps")];
    if (exposed.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: obs.sourceMaps[0]!.scriptUrl, summary: "Script có tham chiếu source map nhưng không tải công khai được.", explanation: "Mã nguồn gốc của bạn không bị lộ.", evidence: obs.sourceMaps.slice(0, 5).map((s) => `${s.mapUrl} → ${s.status}`), references: refs })];
    return [makeFinding({
      ruleId: this.id, title: "Source map JavaScript có thể tải công khai", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: exposed[0]!.mapUrl, references: refs,
      summary: `${exposed.length} file source map được các script của ứng dụng tham chiếu có thể được bất kỳ ai tải về.`,
      explanation: "Source map tiết lộ mã nguồn gốc dễ đọc của bạn — bình luận, cấu trúc thư mục, các route API nội bộ — giúp kẻ tấn công tìm điểm yếu dễ hơn nhiều. Chúng còn có thể chứa bí mật bị gõ cứng trong mã.",
      technical: "Một tham chiếu //# sourceMappingURL trỏ tới phản hồi 200 trông giống source map (JSON có version/sources).",
      evidence: exposed.slice(0, 6).map((s) => `${truncate(s.mapUrl, 200)} → ${s.status}`),
      remediation: {
        summary: "Đừng công khai source map trên production, hoặc chỉ tải chúng lên công cụ theo dõi lỗi.",
        steps: obs.platforms.includes("nextjs") ? ["Next.js: đảm bảo productionBrowserSourceMaps không được bật trong next.config (mặc định là false)."] : ["Tắt xuất source map cho bản build production trong bundler, hoặc chặn *.map ở máy chủ web/CDN."],
        snippets: obs.platforms.includes("nextjs") ? [{ platform: "nextjs", label: "Next.js — next.config.ts", language: "ts", code: "const nextConfig = {\n  productionBrowserSourceMaps: false,\n};\nexport default nextConfig;" }] : [],
      },
    })];
  },
};

const robots: Rule = {
  id: "exposure.robots-txt",
  title: "robots.txt",
  category: CAT,
  run(obs) {
    const f = obs.files.robots;
    if (!f) return [];
    if (!f.present) return [makeFinding({ ruleId: this.id, title: "Không có robots.txt", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: f.url, summary: "Website không có robots.txt.", explanation: "Không phải vấn đề bảo mật. robots.txt chỉ hướng dẫn các trình thu thập tuân thủ (và không bao giờ được dùng để giấu trang riêng tư).", evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`], remediation: null })];
    const interesting = f.body.split(/\r?\n/).map((l) => /^\s*disallow\s*:\s*(\S+)/i.exec(l)?.[1]).filter((p): p is string => !!p && /(admin|backup|private|secret|internal|staging|\.git|\.env|config|dump|database|db\b|phpmyadmin)/i.test(p));
    if (interesting.length) {
      return [makeFinding({ ruleId: this.id, title: "robots.txt liệt kê đường dẫn trông nhạy cảm", category: CAT, severity: "info", confidence: "low", status: "info", affectedUrl: f.url, summary: `robots.txt nêu tên ${interesting.length} đường dẫn trông có vẻ riêng tư.`, explanation: "robots.txt là công khai. Liệt kê các đường dẫn “ẩn” ở đó chỉ quảng cáo chúng cho kẻ tấn công chứ không bảo vệ gì. Bảo vệ thật sự là xác thực.", evidence: interesting.slice(0, 8).map((p) => `Disallow: ${p}`), remediation: { summary: "Đảm bảo các đường dẫn này yêu cầu đăng nhập; bỏ khỏi robots.txt nếu việc chúng tồn tại là nhạy cảm.", snippets: [] }, references: [{ title: "OWASP WSTG: Review Webserver Metafiles", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage" }] })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "robots.txt có mặt và không quảng cáo đường dẫn nhạy cảm.", explanation: "Trình thu thập được hướng dẫn mà không để lộ thứ gì riêng tư.", evidence: [`${f.body.split(/\r?\n/).length} dòng`] })];
  },
};

const sitemap: Rule = {
  id: "exposure.sitemap-xml",
  title: "sitemap.xml",
  category: CAT,
  run(obs) {
    const f = obs.files.sitemap;
    if (!f) return [];
    if (!f.present) return [makeFinding({ ruleId: this.id, title: "Không có sitemap.xml", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: f.url, summary: "Không có sitemap.xml ở vị trí mặc định.", explanation: "Không phải vấn đề bảo mật; sitemap giúp công cụ tìm kiếm. (Nó có thể nằm ở đường dẫn khác được nêu trong robots.txt.)", evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`], remediation: null })];
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "sitemap.xml có mặt.", explanation: "Hãy chắc chắn nó chỉ liệt kê các trang dự định công khai.", evidence: [`${f.contentType || "không rõ loại"}, đã lấy mẫu ${f.body.length} byte`] })];
  },
};

const securityTxt: Rule = {
  id: "exposure.security-txt",
  title: "security.txt (liên hệ báo cáo lỗ hổng)",
  category: CAT,
  run(obs) {
    const f = obs.files.securityTxt;
    if (!f) return [];
    const refs = [{ title: "RFC 9116: security.txt", url: "https://www.rfc-editor.org/rfc/rfc9116" }, { title: "securitytxt.org", url: "https://securitytxt.org/" }];
    if (!f.present) {
      return [makeFinding({ ruleId: this.id, title: "Chưa công bố security.txt", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: f.url, references: refs,
        summary: "Không có /.well-known/security.txt hướng dẫn nhà nghiên cứu cách báo cáo lỗ hổng.", explanation: "Không có đầu mối liên hệ, những nhà nghiên cứu thiện chí phát hiện lỗi có thể không biết liên lạc với bạn bằng cách nào.",
        evidence: [`GET ${f.url} → ${f.status ?? f.error ?? "n/a"}`],
        remediation: { summary: "Công bố /.well-known/security.txt với trường Contact và Expires.", snippets: [{ platform: "generic", label: "/.well-known/security.txt", language: "text", code: "Contact: mailto:security@tenmiencuaban.vn\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: vi, en\nCanonical: https://tenmiencuaban.vn/.well-known/security.txt" }] } })];
    }
    const contact = /^\s*Contact\s*:\s*\S+/im.test(f.body);
    const exp = /^\s*Expires\s*:\s*(\S+)/im.exec(f.body)?.[1];
    const expired = exp ? Date.parse(exp) < Date.now() : false;
    const problems = [!contact ? "thiếu trường Contact" : "", !exp ? "thiếu trường Expires" : "", expired ? `đã hết hạn từ ${exp}` : ""].filter(Boolean);
    if (problems.length) {
      return [makeFinding({ ruleId: this.id, title: "security.txt chưa đầy đủ hoặc đã hết hạn", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: f.url, references: refs,
        summary: `security.txt có vấn đề: ${problems.join(", ")}.`, explanation: "security.txt hết hạn hoặc không có thông tin liên hệ sẽ bị công cụ và nhà nghiên cứu bỏ qua.", evidence: [truncate(f.body.split(/\r?\n/).slice(0, 6).join(" | "), 300)],
        remediation: { summary: "Thêm Contact và ngày Expires trong tương lai (RFC 9116).", snippets: [] } })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: f.url, summary: "security.txt được công bố với thông tin liên hệ và hạn dùng hợp lệ.", explanation: "Nhà nghiên cứu biết nơi gửi báo cáo.", evidence: [`Expires: ${exp}`], references: refs })];
  },
};

// ------------------------------------------------------------------ thư viện JavaScript lỗi thời

function cmp(a: string, b: string): number {
  const x = a.split(".").map(Number), y = b.split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

interface LibRule {
  name: string;
  patterns: RegExp[];
  assess(v: string): { severity: Severity; reason: string } | null;
}

const V = String.raw`v?(\d+\.\d+(?:\.\d+)?)`;
/** Dấu phân tách giữa tên thư viện và số phiên bản trong URL: "-", ".", "@", "/" cùng hậu tố ".js" kiểu cdnjs ("moment.js/2.18.1/"). */
const SEP = String.raw`(?:\.js)?(?:\.min)?[-.@/]`;
const lib = (name: string, ...patterns: RegExp[]) => ({ name, patterns });
export const LIBRARIES: LibRule[] = [
  { ...lib("jQuery", new RegExp(String.raw`jquery[-.]${V}(?:\.min)?\.js`, "i"), new RegExp(String.raw`jquery[@/]${V}`, "i"), new RegExp(String.raw`jQuery(?: JavaScript Library)? ${V}`)),
    assess: (v) => (cmp(v, "3.5.0") < 0 ? { severity: "medium", reason: "các phiên bản trước 3.5.0 có lỗ hổng XSS (CVE-2020-11022, CVE-2020-11023)" } : null) },
  { ...lib("jQuery UI", new RegExp(String.raw`jquery[-.]?ui${SEP}${V}`, "i"), new RegExp(String.raw`jqueryui/${V}`, "i"), new RegExp(String.raw`jQuery UI - ${V}`)),
    assess: (v) => (cmp(v, "1.13.0") < 0 ? { severity: "medium", reason: "các phiên bản trước 1.13.0 có lỗ hổng XSS (CVE-2021-41182/41183/41184)" } : null) },
  { ...lib("Bootstrap", new RegExp(String.raw`bootstrap(?:\.bundle)?${SEP}${V}`, "i"), new RegExp(String.raw`Bootstrap ${V}`)),
    assess: (v) => {
      const major = Number(v.split(".")[0]);
      return (major < 3 || (major === 3 && cmp(v, "3.4.1") < 0) || (major === 4 && cmp(v, "4.3.1") < 0))
        ? { severity: "medium", reason: "có lỗ hổng XSS trong tooltip/popover (CVE-2019-8331); cần ≥ 3.4.1 hoặc ≥ 4.3.1" } : null;
    } },
  { ...lib("AngularJS", new RegExp(String.raw`angularjs/${V}/`, "i"), new RegExp(String.raw`angular\.js/${V}/`, "i"), new RegExp(String.raw`angular[-.]${V}(?:\.min)?\.js`, "i"), new RegExp(String.raw`AngularJS ${V}`)),
    assess: (v) => (Number(v.split(".")[0]) === 1 ? { severity: "medium", reason: "AngularJS 1.x đã hết hỗ trợ từ 01/2022; nhiều lỗ hổng sandbox/XSS sẽ không còn được vá" } : null) },
  { ...lib("lodash", new RegExp(String.raw`lodash${SEP}${V}`, "i"), new RegExp(String.raw`lodash ${V}`)),
    assess: (v) => (cmp(v, "4.17.21") < 0 ? { severity: "low", reason: "các phiên bản trước 4.17.21 có lỗ hổng prototype pollution/command injection (CVE-2020-8203, CVE-2021-23337)" } : null) },
  { ...lib("Moment.js", new RegExp(String.raw`moment${SEP}${V}`, "i")),
    assess: (v) => (cmp(v, "2.29.4") < 0 ? { severity: "low", reason: "các phiên bản trước 2.29.4 có lỗ hổng ReDoS (CVE-2022-31129)" } : null) },
  { ...lib("Handlebars", new RegExp(String.raw`handlebars(?:\.runtime)?${SEP}${V}`, "i")),
    assess: (v) => (cmp(v, "4.7.7") < 0 ? { severity: "low", reason: "các phiên bản trước 4.7.7 có lỗ hổng prototype pollution/thực thi mã (CVE-2021-23369)" } : null) },
  { ...lib("Vue 2", new RegExp(String.raw`vue(?:\.runtime[\w.]*)?${SEP}v?(2\.\d+\.\d+)`, "i"), new RegExp(String.raw`Vue\.js v(2\.\d+\.\d+)`)),
    assess: () => ({ severity: "low", reason: "Vue 2 đã hết hỗ trợ từ 31/12/2023 nên sẽ không nhận thêm bản vá bảo mật" }) },
];

export interface DetectedLib { name: string; version: string; source: string; severity: Severity | null; reason: string | null }

export function detectLibraries(obs: Observations): DetectedLib[] {
  const found = new Map<string, DetectedLib>();
  const consider = (text: string, source: string) => {
    for (const lib of LIBRARIES) {
      for (const re of lib.patterns) {
        const m = re.exec(text);
        if (!m?.[1]) continue;
        const key = `${lib.name}@${m[1]}`;
        if (found.has(key)) break;
        const a = lib.assess(m[1]);
        found.set(key, { name: lib.name, version: m[1], source, severity: a?.severity ?? null, reason: a?.reason ?? null });
        break;
      }
    }
  };
  for (const s of obs.html?.scripts ?? []) {
    if (s.url) consider(s.url, s.url);
    const head = (s.content ?? s.fetched?.body ?? "").slice(0, 600);
    if (head) consider(head, s.url ?? "script inline");
  }
  for (const c of obs.html?.stylesheets ?? []) consider(c.href, c.href); // ví dụ bootstrap.min.css
  return [...found.values()];
}

const outdatedLibraries: Rule = {
  id: "exposure.outdated-libraries",
  title: "Thư viện JavaScript không nằm trong danh sách lỗ hổng đã biết",
  category: CAT,
  run(obs) {
    const libs = detectLibraries(obs);
    if (libs.length === 0 || !obs.page) return [];
    const url = obs.page.finalUrl;
    const bad = libs.filter((l) => l.severity);
    const refs = [{ title: "OWASP Top 10 A06:2021 — Vulnerable and Outdated Components", url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" }];
    if (bad.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `Nhận diện ${libs.length} thư viện (${libs.slice(0, 4).map((l) => `${l.name} ${l.version}`).join(", ")}); không có phiên bản nào nằm trong danh sách lỗ hổng đã biết của chúng tôi.`, explanation: "Danh sách của chúng tôi chỉ gồm các thư viện phổ biến và lỗ hổng nổi tiếng. Hãy dùng thêm npm audit / Dependabot cho kiểm tra đầy đủ.", evidence: libs.slice(0, 8).map((l) => `${l.name} ${l.version} — ${truncate(l.source, 140)}`), references: refs })];
    }
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    const worst = bad.reduce<Severity>((w, l) => (order.indexOf(l.severity!) < order.indexOf(w) ? l.severity! : w), "info");
    return [makeFinding({
      ruleId: this.id, title: "Website dùng thư viện JavaScript có lỗ hổng đã biết hoặc đã hết hỗ trợ", category: CAT, severity: worst, confidence: "medium", status: "fail", affectedUrl: url, references: refs,
      summary: `Phát hiện ${bad.length} thư viện có vấn đề: ${bad.map((l) => `${l.name} ${l.version}`).join(", ")}.`,
      explanation: "Lỗ hổng của thư viện phổ biến được công bố rộng rãi và có công cụ dò tìm tự động. Khả năng bị khai thác còn phụ thuộc cách website dùng thư viện, nhưng cập nhật là cách rẻ nhất để loại bỏ rủi ro.",
      technical: bad.map((l) => `${l.name} ${l.version}: ${l.reason}`).join("\n") + "\nPhiên bản được đọc từ tên file/URL hoặc dòng chú thích đầu file; độ tin cậy vừa phải vì file có thể đã được vá riêng.",
      evidence: bad.map((l) => `${l.name} ${l.version} — ${truncate(l.source, 140)}`),
      remediation: { summary: "Nâng cấp các thư viện lên phiên bản đã vá (hoặc thay thế nếu đã hết hỗ trợ).", steps: ["Dự án npm: chạy npm audit rồi npm update <tên-gói>; bật Dependabot hoặc Renovate để tự động nhắc cập nhật.", "Nếu tải từ CDN: đổi số phiên bản trong URL và thêm integrity (SRI) cho file mới.", "Thư viện đã hết hỗ trợ (AngularJS 1.x, Vue 2): lập kế hoạch di chuyển sang phiên bản còn được hỗ trợ."], snippets: [] },
    })];
  },
};

// ------------------------------------------------------------------ nguy cơ chiếm subdomain

interface TakeoverSig { name: string; body: RegExp; cname: RegExp; needCname?: boolean }
export const TAKEOVER_SIGS: TakeoverSig[] = [
  { name: "GitHub Pages", body: /There isn't a GitHub Pages site here/i, cname: /\.github\.io$/i },
  { name: "Heroku", body: /herokucdn\.com\/error-pages\/no-such-app\.html/i, cname: /(herokuapp|herokudns)\.com$/i },
  // Câu chữ chung chung chỉ được tin khi DNS thật sự trỏ tới Heroku.
  { name: "Heroku", body: /No such app/i, cname: /(herokuapp|herokudns)\.com$/i, needCname: true },
  { name: "Amazon S3", body: /<Code>NoSuchBucket<\/Code>|The specified bucket does not exist/i, cname: /\.amazonaws\.com$/i },
  { name: "Shopify", body: /Sorry, this shop is currently unavailable/i, cname: /myshopify\.com$/i },
  { name: "Fastly", body: /Fastly error: unknown domain/i, cname: /fastly\.net$/i },
  { name: "Tumblr", body: /Whatever you were looking for doesn't currently exist at this address/i, cname: /tumblr\.com$/i },
  { name: "Pantheon", body: /The gods are wise, but do not know of the site which you seek/i, cname: /pantheonsite\.io$/i },
  { name: "Surge.sh", body: /project not found/i, cname: /surge\.sh$/i, needCname: true },
];

const subdomainTakeover: Rule = {
  id: "exposure.subdomain-takeover",
  title: "Không có dấu hiệu có thể bị chiếm quyền tên miền (subdomain takeover)",
  category: CAT,
  run(obs) {
    const p = obs.page;
    if (!p || !p.body) return [];
    const cnames = obs.dns?.cname ?? [];
    const refs = [{ title: "OWASP WSTG: Test for Subdomain Takeover", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover" }];
    for (const sig of TAKEOVER_SIGS) {
      if (!sig.body.test(p.body)) continue;
      const cnameHit = cnames.find((c) => sig.cname.test(c));
      if (sig.needCname && !cnameHit) continue;
      return [makeFinding({
        ruleId: this.id, title: `Tên miền có dấu hiệu trỏ tới dịch vụ ${sig.name} chưa được cấu hình`, category: CAT,
        severity: cnameHit ? "high" : "medium", confidence: cnameHit ? "high" : "medium", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Trang trả về thông báo lỗi đặc trưng của ${sig.name} (“tài nguyên không tồn tại”)${cnameHit ? ` và DNS có CNAME trỏ tới ${cnameHit}` : ""}.`,
        explanation: "Khi bản ghi DNS vẫn trỏ tới một dịch vụ bên ngoài nhưng tài khoản/ứng dụng ở đó đã bị xoá, kẻ khác có thể đăng ký lại đúng tên đó và đưa nội dung của họ lên tên miền của bạn — dùng để lừa đảo, đánh cắp cookie hoặc phát tán mã độc dưới uy tín của bạn.",
        technical: `Nhận diện bằng dấu vân tay thông báo lỗi của ${sig.name}${cnameHit ? ` + CNAME → ${cnameHit}` : ""}. ${cnameHit ? "" : "Chưa thấy CNAME nên độ tin cậy ở mức vừa."}`,
        evidence: [`HTTP ${p.status} tại ${p.finalUrl}`, ...(cnameHit ? [`CNAME: ${cnameHit}`] : []), `Dấu vân tay: ${sig.name}`],
        remediation: { summary: "Xoá bản ghi DNS không còn dùng, hoặc tạo lại tài nguyên trên dịch vụ đó và xác minh quyền sở hữu tên miền.", steps: ["Nếu tên miền này không còn dùng: xoá bản ghi CNAME/A trong DNS ngay.", `Nếu vẫn cần: đăng nhập ${sig.name}, tạo lại site/ứng dụng và gắn đúng tên miền tuỳ chỉnh.`, "Rà soát toàn bộ bản ghi DNS định kỳ để tìm các CNAME “mồ côi”."], snippets: [] },
      })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Không có thông báo lỗi “tài nguyên chưa được cấu hình” của các nền tảng hosting phổ biến.", explanation: "Không có dấu hiệu tên miền trỏ tới một dịch vụ bên ngoài đã bị xoá.", evidence: cnames.length ? [`CNAME: ${cnames.join(", ")}`] : ["Không có CNAME"] })];
  },
};

// ------------------------------------------------------------------ trang lỗi lộ thông tin

/**
 * scope "error": chỉ tìm trong phản hồi của đường dẫn KHÔNG tồn tại (trang chủ có thể hợp lệ chứa chữ giống thế này,
 * ví dụ bài hướng dẫn lập trình). scope "any": dấu hiệu đủ đặc trưng để áp dụng cả trang chủ.
 */
interface ErrSig { id: string; label: string; re: RegExp; severity: Severity; confidence: "high" | "medium"; why: string; scope: "error" | "any" }
export const ERROR_SIGS: ErrSig[] = [
  { id: "django-debug", label: "Trang gỡ lỗi Django (DEBUG=True)", re: /You're seeing this error because you have\s*<code>DEBUG = True|Django Version:|<title>Page not found at \//i, severity: "high", confidence: "high", why: "chế độ debug của Django hiển thị cấu hình, đường dẫn và biến nội bộ", scope: "any" },
  { id: "laravel-debug", label: "Trang gỡ lỗi Laravel", re: /Illuminate\\|vendor\/laravel\/framework|facade\/ignition|Whoops! There was an error/i, severity: "high", confidence: "high", why: "chế độ APP_DEBUG của Laravel có thể lộ cấu hình, biến môi trường và mã nguồn", scope: "any" },
  { id: "python-traceback", label: "Stack trace Python", re: /Traceback \(most recent call last\)/, severity: "medium", confidence: "high", why: "stack trace tiết lộ đường dẫn file và cấu trúc mã nguồn", scope: "error" },
  { id: "java-trace", label: "Stack trace Java", re: /\bat [\w$.]+\([\w$]+\.java:\d+\)/, severity: "medium", confidence: "high", why: "stack trace Java tiết lộ tên lớp, đường dẫn và đôi khi cả thông tin phiên bản", scope: "error" },
  { id: "php-error", label: "Lỗi PHP có đường dẫn file", re: /(?:Fatal error|Warning|Notice|Parse error)(?:<\/b>)?:\s.{0,160}?\sin\s(?:<b>)?\/[\w\/.\-]+(?:<\/b>)?\son\sline\s(?:<b>)?\d+|Stack trace:\s*#0 /i, severity: "medium", confidence: "high", why: "thông báo lỗi PHP lộ đường dẫn tuyệt đối trên máy chủ", scope: "error" },
  { id: "aspnet-error", label: "Trang lỗi ASP.NET chi tiết", re: /Server Error in '\/' Application|<title>Runtime Error<\/title>|Version Information:\s*Microsoft \.NET Framework/i, severity: "medium", confidence: "high", why: "trang lỗi ASP.NET lộ phiên bản framework và chi tiết ngoại lệ", scope: "any" },
  { id: "node-trace", label: "Stack trace Node.js", re: /\bat\s+[\w.<>$ ]+\s\((?:\/|[A-Za-z]:\\)[^)]*node_modules[^)]*:\d+:\d+\)|(?:Reference|Type|Syntax)?Error: .*\n\s+at .*\(.*:\d+:\d+\)/, severity: "medium", confidence: "medium", why: "stack trace Node.js lộ đường dẫn thư mục và tên module", scope: "error" },
  { id: "spring-whitelabel", label: "Whitelabel Error Page (Spring Boot)", re: /Whitelabel Error Page/, severity: "low", confidence: "high", why: "lộ rằng ứng dụng dùng Spring Boot và có thể kèm thông điệp lỗi nội bộ", scope: "any" },
  { id: "dir-listing", label: "Liệt kê thư mục (directory listing)", re: /<title>Index of \/|<h1>Index of \//i, severity: "medium", confidence: "high", why: "người lạ duyệt được toàn bộ file trong thư mục", scope: "any" },
  { id: "apache-banner", label: "Chân trang lỗi Apache có phiên bản", re: /Apache\/\d+\.\d+(?:\.\d+)?\s*\([^)]*\)\s*Server at/i, severity: "low", confidence: "high", why: "chân trang lỗi lộ phiên bản Apache và hệ điều hành", scope: "error" },
  { id: "nginx-banner", label: "Trang lỗi Nginx có phiên bản", re: /<center>nginx\/\d+\.\d+(?:\.\d+)?<\/center>/i, severity: "low", confidence: "high", why: "trang lỗi lộ chính xác phiên bản Nginx", scope: "error" },
];

const errorPage: Rule = {
  id: "exposure.error-page-disclosure",
  title: "Trang lỗi không lộ thông tin nội bộ",
  category: CAT,
  run(obs) {
    const targets = [obs.notFound, obs.page].filter((r): r is NonNullable<typeof r> => !!r && !r.error && !!r.body);
    if (targets.length === 0) return [];
    const refs = [OWASPErr(), { title: "MDN: HTTP 404", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/404" }];
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const r of targets) {
      for (const sig of ERROR_SIGS) {
        if (sig.scope === "error" && r !== obs.notFound) continue;
        const m = sig.re.exec(r.body);
        if (!m || seen.has(sig.id)) continue;
        seen.add(sig.id);
        out.push(makeFinding({
          ruleId: this.id, key: sig.id, title: `${sig.label} bị lộ`, category: CAT, severity: sig.severity, confidence: sig.confidence, status: "fail", affectedUrl: r.finalUrl, references: refs,
          summary: `Trang ${r === obs.notFound ? "lỗi (đường dẫn không tồn tại)" : "chủ"} trả về nội dung đặc trưng của ${sig.label.toLowerCase()}: ${sig.why}.`,
          explanation: "Thông báo lỗi chi tiết giúp kẻ tấn công biết chính xác công nghệ, phiên bản và cấu trúc thư mục bạn dùng, từ đó chọn đúng kỹ thuật tấn công. Môi trường production chỉ nên hiển thị trang lỗi chung chung.",
          technical: `Khớp mẫu ${sig.id} trong phản hồi HTTP ${r.status}. Đoạn khớp: ${truncate(m[0].replace(/\s+/g, " "), 100)}`,
          evidence: [`HTTP ${r.status} tại ${r.finalUrl}`, `Mẫu: ${sig.label}`, `Trích: ${truncate(m[0].replace(/\s+/g, " "), 100)}`],
          remediation: { summary: "Tắt chế độ debug và hiển thị trang lỗi tuỳ chỉnh, không kèm chi tiết kỹ thuật.", steps: ["Django: DEBUG = False  ·  Laravel: APP_DEBUG=false  ·  Spring: server.error.include-stacktrace=never", "PHP: display_errors = Off, log_errors = On  ·  ASP.NET: <customErrors mode=\"On\" />", "Nginx/Apache: đặt error_page/ErrorDocument tuỳ chỉnh và ẩn phiên bản (server_tokens off / ServerTokens Prod).", "Ghi chi tiết lỗi vào nhật ký phía máy chủ thay vì trả cho trình duyệt."], snippets: [] },
        }));
      }
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: obs.notFound?.finalUrl ?? obs.page?.finalUrl ?? null, summary: "Trang lỗi (đường dẫn không tồn tại) không chứa stack trace, đường dẫn máy chủ hay thông tin debug.", explanation: "Kẻ tấn công không lấy được thông tin nội bộ từ thông báo lỗi.", evidence: obs.notFound ? [`HTTP ${obs.notFound.status} tại ${obs.notFound.finalUrl}`] : [] })];
    }
    return out;
  },
};

function OWASPErr() {
  return { title: "OWASP WSTG: Error Handling", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling" };
}

// ---------------------------------------------------------------- phân tích tĩnh: không thêm request nào

const PRIVATE_IP = /(?<![\d.])(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})(?::\d{2,5})?(?![\d.])/g;
const INTERNAL_HOST = /\bhttps?:\/\/((?:[a-z0-9-]+\.)+(?:internal|corp|lan|intranet|local)|localhost|127\.0\.0\.1)(?::\d{2,5})?(?:\/|["'\s)])/gi;
const SDK_NOISE = /(w3\.org|schemas\.|xmlns|example\.|\.local\b.*(?:webpack|hot-update))/i;

/** Địa chỉ nội bộ (IP riêng, *.internal, localhost…) bị đóng gói vào trang công khai. */
const internalReferences: Rule = {
  id: "exposure.internal-references",
  title: "Không lộ địa chỉ mạng nội bộ",
  category: CAT,
  run(obs) {
    const docs = publicDocuments(obs);
    if (docs.length === 0) return [];
    const hits = new Map<string, string>(); // địa chỉ → URL tài liệu
    for (const d of docs) {
      for (const m of d.text.matchAll(PRIVATE_IP)) hits.set(m[1]!, d.url);
      for (const m of d.text.matchAll(INTERNAL_HOST)) if (!SDK_NOISE.test(m[0])) hits.set(m[1]!.toLowerCase(), d.url);
      if (hits.size >= 8) break;
    }
    const refs = [OWASP("Information_Exposure_Through_Query_Strings_in_GET_Request.html", "OWASP: Information exposure")];
    if (hits.size === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: docs[0]!.url, summary: "Không thấy địa chỉ IP riêng hay tên miền nội bộ trong trang và script công khai.", explanation: "Kẻ tấn công không biết được cấu trúc mạng nội bộ của bạn qua mã phía trình duyệt.", evidence: [] })];
    return [makeFinding({
      ruleId: this.id, title: "Trang công khai tham chiếu địa chỉ mạng nội bộ", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: [...hits.values()][0], references: refs,
      key: [...hits.keys()].sort().join(",").slice(0, 80),
      summary: `${hits.size} địa chỉ nội bộ xuất hiện trong mã công khai (ví dụ: ${[...hits.keys()][0]}).`,
      explanation: "Địa chỉ IP riêng, máy chủ *.internal hoặc localhost trong mã trình duyệt cho kẻ tấn công biết cấu trúc mạng và tên dịch vụ nội bộ, và thường là dấu hiệu cấu hình môi trường phát triển bị đưa nhầm lên production.",
      technical: "Khớp mẫu IP thuộc dải RFC 1918 / link-local hoặc tên miền .internal/.corp/.lan/.local/localhost trong HTML hoặc JavaScript cùng origin.",
      evidence: [...hits].slice(0, 6).map(([h, u]) => `${h} trong ${truncate(u, 120)}`),
      remediation: { summary: "Dùng biến môi trường cho từng môi trường và không đóng gói địa chỉ nội bộ vào bản build production.", steps: ["Tìm các địa chỉ trên trong mã nguồn/biến môi trường lúc build.", "Gọi dịch vụ nội bộ từ phía máy chủ, không từ trình duyệt."], snippets: [] },
    })];
  },
};

const COMMENT_SENSITIVE = /(password|passwd|secret|api[_-]?key|token|credential|todo\s*[:\-]?\s*(?:remove|delete|fix|hack)|fixme|hack|staging|internal use)/i;

/** Bình luận HTML chứa từ khoá nhạy cảm. Chỉ ghi nhận TỪ KHOÁ + vị trí, không lưu nguyên văn (có thể chứa bí mật). */
const htmlComments: Rule = {
  id: "exposure.html-comments",
  title: "Bình luận HTML không lộ thông tin nhạy cảm",
  category: CAT,
  run(obs) {
    const p = obs.page;
    if (!p || !/html/i.test(p.contentType)) return [];
    const found: string[] = [];
    for (const m of p.body.matchAll(/<!--(?!\[if|<!\]|\s*\/?ko\b)([\s\S]{4,600}?)-->/g)) {
      const k = COMMENT_SENSITIVE.exec(m[1]!)?.[1];
      if (k) found.push(k.toLowerCase().replace(/\s+/g, " "));
    }
    if (found.length === 0) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Bình luận HTML (nếu có) không chứa từ khoá nhạy cảm.", explanation: "Ghi chú của lập trình viên không bị lộ ra khách truy cập.", evidence: [] })];
    const uniq = [...new Set(found)];
    return [makeFinding({
      ruleId: this.id, title: "Bình luận HTML có từ khoá nhạy cảm", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: p.finalUrl, key: "comments",
      references: [OWASP("Information_Exposure_Through_Query_Strings_in_GET_Request.html", "OWASP: Information exposure")],
      summary: `${found.length} bình luận HTML chứa từ khoá như "${uniq[0]}".`,
      explanation: "Bình luận trong HTML ai cũng đọc được qua \"Xem nguồn trang\". Ghi chú về mật khẩu, token, môi trường staging hay việc cần sửa có thể giúp kẻ tấn công.",
      technical: "Khớp từ khoá nhạy cảm bên trong <!-- … -->. Độ tin cậy thấp vì từ khoá có thể vô hại; nội dung bình luận không được lưu để tránh làm lộ bí mật.",
      evidence: uniq.slice(0, 6).map((k) => `từ khoá: ${k}`),
      remediation: { summary: "Xoá bình luận khỏi HTML production (minify HTML hoặc loại bỏ khi build).", steps: ["Mở \"Xem nguồn trang\" và tìm các từ khoá trên.", "Bật bước loại bỏ bình luận trong quy trình build."], snippets: [] },
    })];
  },
};

export const exposureRules: Rule[] = [internalReferences, htmlComments, secrets, publicConfig, sourceMaps, robots, sitemap, securityTxt, outdatedLibraries, subdomainTakeover, errorPage];
