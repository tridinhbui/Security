import { getDomain } from "tldts";
import type { DnsInfo, Finding, Observations, Rule } from "../types";
import { header, headerEvidence, livePage, makeFinding, MDN, pass, truncate } from "../util";

const CAT = "Configuration" as const;

const serverDisclosure: Rule = {
  id: "config.server-disclosure",
  title: "Không để lộ phiên bản máy chủ và framework",
  category: CAT,
  run(obs) {
    const p = livePage(obs);
    if (!p) return [];
    const names = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache", "x-runtime"];
    const present = names.filter((n) => header(p.headers, n) !== undefined);
    const versioned = present.filter((n) => /\d+\.\d+/.test(header(p.headers, n)!));
    const refs = [{ title: "OWASP WSTG: Fingerprint Web Server", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server" }];
    if (versioned.length) {
      return [makeFinding({
        ruleId: this.id, title: "Phiên bản phần mềm bị lộ trong header phản hồi", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: p.finalUrl, references: refs,
        summary: `Header tiết lộ phiên bản chính xác: ${versioned.map((n) => `${n}: ${truncate(header(p.headers, n)!, 60)}`).join("; ")}.`,
        explanation: "Kẻ tấn công dùng số phiên bản để tra cứu các lỗ hổng đã biết của đúng phần mềm bạn chạy. Ẩn phiên bản không thay thế việc cập nhật phần mềm, nhưng bỏ đi một gợi ý miễn phí.",
        technical: "Chuỗi phiên bản trong các header kiểu Server / X-Powered-By.", evidence: present.map((n) => headerEvidence(p.headers, n)),
        remediation: {
          summary: "Bỏ thông tin phiên bản (và X-Powered-By) khỏi phản hồi — đồng thời giữ phần mềm luôn được cập nhật.",
          steps: ["Nginx: server_tokens off;", "Apache: ServerTokens Prod và ServerSignature Off", "Express: app.disable('x-powered-by') (hoặc dùng helmet)", "Next.js: đặt poweredByHeader: false trong next.config"],
          snippets: obs.platforms.includes("nextjs") ? [{ platform: "nextjs", label: "Next.js — next.config.ts", language: "ts", code: "const nextConfig = {\n  poweredByHeader: false,\n};\nexport default nextConfig;" }] : [],
        },
      })];
    }
    if (present.length) {
      return [makeFinding({ ruleId: this.id, title: "Tên công nghệ hiện trong header phản hồi", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: p.finalUrl, references: refs,
        summary: `Header nêu tên hệ thống (${present.join(", ")}) nhưng không kèm phiên bản.`, explanation: "Rủi ro thấp. Nêu tên công nghệ là phổ biến và hầu như vô hại nếu không có số phiên bản.", evidence: present.map((n) => headerEvidence(p.headers, n)), remediation: null })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: p.finalUrl, summary: "Không có header nhận diện máy chủ hay framework nào bị lộ.", explanation: "Kẻ tấn công có ít thông tin hơn để dựa vào.", evidence: [] })];
  },
};

const techFingerprint: Rule = {
  id: "config.technology",
  title: "Công nghệ được nhận diện",
  category: CAT,
  run(obs) {
    if (obs.technologies.length === 0 || !obs.page) return [];
    return [makeFinding({
      ruleId: this.id, title: "Dấu vân tay công nghệ phía giao diện", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `Chúng tôi nhận diện được: ${obs.technologies.join(", ")}.`, explanation: "Dùng để điều chỉnh hướng dẫn khắc phục. Nhận diện dựa vào dấu hiệu công khai nên có thể thiếu hoặc sai, và chúng tôi chỉ hiển thị đoạn cấu hình theo framework khi việc nhận diện đáng tin cậy.",
      evidence: obs.technologies.map((t) => `• ${t}`), remediation: null,
    })];
  },
};

const REDIRECT_CHAIN_WARN = 4;

const redirects: Rule = {
  id: "config.suspicious-redirects",
  title: "Hành vi chuyển hướng",
  category: CAT,
  run(obs: Observations): Finding[] {
    const out: Finding[] = [];
    const records = [obs.https, obs.http].filter((r): r is NonNullable<typeof r> => !!r);
    for (const r of records) {
      const label = r === obs.https ? "https" : "http";
      const hops = r.chain;
      for (let i = 0; i < hops.length - 1; i++) {
        const cur = hops[i]!, next = hops[i + 1]!;
        if (cur.url.startsWith("https://") && next.url.startsWith("http://")) {
          out.push(makeFinding({ ruleId: this.id, key: `downgrade:${label}`, title: "Chuyển hướng hạ cấp từ HTTPS xuống HTTP", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: cur.url,
            references: [MDN("Web/HTTP/Guides/Redirections", "MDN: Redirections")],
            summary: "Một URL HTTPS an toàn chuyển khách sang URL http:// không mã hoá.", explanation: "Khách rời khỏi kết nối mã hoá giữa chừng, làm mất toàn bộ tác dụng của HTTPS với các request đó.",
            evidence: [`${cur.status} ${cur.url} → ${next.url}`], remediation: { summary: "Chuyển hướng tới phiên bản https:// của URL (kiểm tra quy tắc redirect, cấu hình host chính tắc và các header proxy như X-Forwarded-Proto).", snippets: [] } }));
          break;
        }
      }
      if (hops.length > REDIRECT_CHAIN_WARN) {
        out.push(makeFinding({ ruleId: this.id, key: `long:${label}`, title: "Chuỗi chuyển hướng quá dài", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: hops[0]?.url ?? null,
          summary: `Để tới được trang phải qua ${hops.length} bước chuyển hướng.`, explanation: "Chuỗi dài làm chậm website, và mỗi bước thêm là một chỗ có thể mắc lỗi hạ cấp hoặc bị chiếm.",
          evidence: hops.map((h) => `${h.status} ${truncate(h.url, 120)}`), remediation: { summary: "Chuyển hướng thẳng tới URL chính tắc cuối cùng chỉ trong một bước.", snippets: [] } }));
      }
      const ipHop = hops.slice(1).find((h) => /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:|\/|$)|^https?:\/\/\[/.test(h.url));
      if (ipHop) {
        out.push(makeFinding({ ruleId: this.id, key: `ip:${label}`, title: "Chuyển hướng tới địa chỉ IP trần", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: hops[0]?.url ?? null,
          summary: "Website chuyển khách tới một địa chỉ IP thay vì tên miền.", explanation: "URL dạng IP không thể có chứng chỉ HTTPS thông thường và là mẫu hình hay thấy ở website bị xâm nhập hoặc cấu hình sai.",
          evidence: [`→ ${truncate(ipHop.url, 160)}`], remediation: { summary: "Chuyển hướng tới tên miền của bạn.", snippets: [] } }));
      }
      if (r.error?.blocked && hops.length > 0) {
        out.push(makeFinding({ ruleId: this.id, key: `blocked:${label}`, title: "Một chuyển hướng tới địa chỉ không công khai đã bị từ chối", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: hops[0]?.url ?? null,
          summary: "Website chuyển hướng tới đích mà VibeSec sẽ không kết nối (nội bộ, riêng tư hoặc cổng không chuẩn).", explanation: "Chúng tôi chỉ quét website công khai trên cổng chuẩn. Nếu chuyển hướng này là ngoài ý muốn, hãy kiểm tra cấu hình sai hoặc dấu hiệu bị xâm nhập.",
          evidence: [`${r.error.code}: ${r.error.message}`], remediation: null }));
      }
    }
    const main = obs.page;
    if (main && obs.html?.metaRefresh) {
      const m = /url\s*=\s*['"]?([^'";\s]+)/i.exec(obs.html.metaRefresh);
      if (m) {
        try {
          const target = new URL(m[1]!, main.finalUrl);
          const a = getDomain(target.hostname), b = getDomain(new URL(main.finalUrl).hostname);
          if (a && b && a !== b) out.push(makeFinding({ ruleId: this.id, key: "meta-refresh", title: "Trang tự động chuyển sang tên miền khác", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: main.finalUrl,
            summary: `Thẻ <meta refresh> đưa khách tới ${target.hostname}.`, explanation: "Meta-refresh sang website khác là dấu hiệu thường thấy của trang bị chiếm hoặc tên miền đậu (parked).", evidence: [`<meta http-equiv="refresh" content="${truncate(obs.html.metaRefresh, 120)}">`], remediation: { summary: "Xác nhận chuyển hướng này là chủ ý; nếu không, hãy gỡ và điều tra.", snippets: [] } }));
        } catch { /* bỏ qua URL không hợp lệ */ }
      }
    }
    if (obs.https && obs.https.chain.length > 0) {
      const first = new URL(obs.https.chain[0]!.url).hostname;
      const last = new URL(obs.https.finalUrl).hostname;
      const a = getDomain(first), b = getDomain(last);
      if (a && b && a !== b && out.length === 0) {
        out.push(makeFinding({ ruleId: this.id, key: "cross-domain", title: "Website chuyển hướng sang tên miền khác", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: obs.https.chain[0]!.url,
          summary: `${first} chuyển hướng tới ${last}.`, explanation: "Thường gặp khi đổi thương hiệu hoặc dùng tên miền chính tắc. Nên xem lại để chắc đây là chủ ý.", evidence: obs.https.chain.map((h) => `${h.status} ${truncate(h.url, 120)}`), remediation: null }));
      }
    }
    if (out.length === 0 && records.length) {
      return [pass({ ruleId: this.id, title: "Không có chuyển hướng đáng ngờ", category: CAT, affectedUrl: obs.https?.requestedUrl ?? null, summary: "Các chuyển hướng (nếu có) ở lại trong cùng website và không bao giờ hạ cấp xuống HTTP.", explanation: "Khách tới đúng nơi họ mong đợi.", evidence: [] })];
    }
    return out;
  },
};

// ------------------------------------------------------------------ DNS & bảo mật email

/** Đếm số truy vấn DNS mà SPF kích hoạt (giới hạn của RFC 7208 là 10). */
export function spfLookupCount(spf: string): number {
  return (spf.match(/\b(include:|a(?=[:/\s]|$)|mx(?=[:/\s]|$)|ptr|exists:|redirect=)/gi) ?? []).length;
}

function dmarcPolicy(d: string): { p: string; pct: number; rua: boolean } {
  const tag = (k: string) => new RegExp(`(?:^|;)\\s*${k}\\s*=\\s*([^;\\s]+)`, "i").exec(d)?.[1];
  return { p: (tag("p") ?? "none").toLowerCase(), pct: Number(tag("pct") ?? 100), rua: !!tag("rua") };
}

const dnsRule: Rule = {
  id: "config.dns-email-security",
  title: "Metadata bảo mật DNS & email",
  category: CAT,
  run(obs) {
    const d: DnsInfo | null = obs.dns;
    if (!d || !d.domain) return [];
    const out: Finding[] = [];
    const dm = d.domain;
    const refs = [{ title: "dmarc.org overview", url: "https://dmarc.org/overview/" }];

    // ---- DMARC
    if (d.dmarc === null) {
      out.push(makeFinding({ ruleId: this.id, key: "dmarc", title: "Chưa có bản ghi DMARC", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null, references: refs,
        summary: `${dm} chưa có chính sách DMARC trong DNS.`, explanation: "Không có DMARC, kẻ tấn công có thể gửi email giả mạo tên miền của bạn (lừa đảo). Điều này quan trọng nếu tên miền có gửi email, hoặc có thể bị lợi dụng để giả mạo.",
        technical: `Không có bản ghi TXT tại _dmarc.${dm}. Độ tin cậy thấp vì chúng tôi không biết tên miền này có gửi email hay không.`, evidence: [`TXT _dmarc.${dm}: (không có)`],
        remediation: { summary: "Công bố bản ghi DMARC, bắt đầu ở chế độ giám sát.", snippets: [{ platform: "generic", label: `TXT _dmarc.${dm}`, language: "text", code: `v=DMARC1; p=none; rua=mailto:dmarc@${dm}` }] } }));
    } else if (typeof d.dmarc === "string") {
      const pol = dmarcPolicy(d.dmarc);
      if (pol.p === "none") {
        out.push(makeFinding({ ruleId: this.id, key: "dmarc-policy", title: "DMARC chỉ ở chế độ giám sát (p=none)", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: null, references: refs,
          summary: "Chính sách DMARC p=none chỉ ghi nhận mà chưa chặn email giả mạo.", explanation: "p=none là điểm xuất phát hợp lý, nhưng để thực sự ngăn giả mạo cần nâng lên quarantine rồi reject sau khi đã xem báo cáo.",
          evidence: [truncate(d.dmarc, 200)], remediation: { summary: "Theo dõi báo cáo DMARC vài tuần rồi nâng chính sách lên p=quarantine, sau đó p=reject.", snippets: [] } }));
      } else if (pol.pct < 100) {
        out.push(makeFinding({ ruleId: this.id, key: "dmarc-pct", title: "DMARC chỉ áp dụng cho một phần email", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: null, references: refs,
          summary: `DMARC có pct=${pol.pct}: chỉ ${pol.pct}% email vi phạm bị xử lý theo chính sách.`, explanation: "Dùng pct<100 là chấp nhận được khi đang triển khai dần, nhưng nên về 100 khi đã ổn.",
          evidence: [truncate(d.dmarc, 200)], remediation: { summary: "Tăng pct lên 100 khi đã chắc chắn email hợp lệ đều qua được.", snippets: [] } }));
      } else {
        out.push(pass({ ruleId: this.id, title: "Chính sách DMARC được công bố", category: CAT, summary: `DMARC ở chế độ ${pol.p}${pol.rua ? " và có địa chỉ nhận báo cáo" : ""}.`, explanation: "Các nhà cung cấp email có thể từ chối thư giả mạo tên miền của bạn.", evidence: [truncate(d.dmarc, 200)] }));
      }
    }

    // ---- SPF
    if (d.spf === null) {
      out.push(makeFinding({ ruleId: this.id, key: "spf", title: "Chưa có bản ghi SPF", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null, references: refs,
        summary: `${dm} chưa có bản ghi SPF.`, explanation: "SPF liệt kê máy chủ nào được phép gửi email cho tên miền của bạn; thiếu nó, thư giả mạo dễ được chuyển tới hơn.",
        technical: `Không có bản ghi TXT bắt đầu bằng v=spf1 tại ${dm}.`, evidence: [`TXT ${dm}: không có v=spf1`],
        remediation: { summary: "Công bố bản ghi SPF liệt kê các nhà cung cấp email của bạn (hoặc v=spf1 -all nếu tên miền không gửi email).", snippets: [{ platform: "generic", label: `TXT ${dm} (tên miền không gửi email)`, language: "text", code: "v=spf1 -all" }] } }));
    } else if (typeof d.spf === "string") {
      const problems: Finding[] = [];
      const qual = /([+~?-]?)all\b/i.exec(d.spf)?.[1] ?? "";
      if (/(^|\s)\+all\b/i.test(d.spf) || /(^|\s)all\b/i.test(d.spf) && qual === "") {
        problems.push(makeFinding({ ruleId: this.id, key: "spf-plus-all", title: "SPF cho phép bất kỳ ai gửi email thay mặt tên miền", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: null, references: refs,
          summary: "SPF kết thúc bằng +all (hoặc all không kèm dấu), nghĩa là mọi máy chủ trên Internet đều được coi là hợp lệ.", explanation: "Điều này vô hiệu hoá hoàn toàn SPF: kẻ tấn công gửi email mạo danh tên miền của bạn mà vẫn “đạt” kiểm tra.",
          evidence: [truncate(d.spf, 200)], remediation: { summary: "Đổi +all thành -all (hoặc ~all trong giai đoạn thử nghiệm) sau khi liệt kê đủ các nguồn gửi hợp lệ.", snippets: [] } }));
      } else if (/\?all\b/i.test(d.spf)) {
        problems.push(makeFinding({ ruleId: this.id, key: "spf-neutral", title: "SPF ở mức trung lập (?all)", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: null, references: refs,
          summary: "SPF kết thúc bằng ?all: không khẳng định thư từ nguồn khác là hợp lệ hay không.", explanation: "Mức trung lập không giúp chặn thư giả mạo.",
          evidence: [truncate(d.spf, 200)], remediation: { summary: "Dùng ~all (soft fail) hoặc -all (hard fail).", snippets: [] } }));
      }
      const lookups = spfLookupCount(d.spf);
      if (lookups > 10) {
        problems.push(makeFinding({ ruleId: this.id, key: "spf-lookups", title: "SPF vượt giới hạn 10 truy vấn DNS", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: null, references: refs,
          summary: `Bản ghi SPF kích hoạt khoảng ${lookups} truy vấn DNS (giới hạn của RFC 7208 là 10).`, explanation: "Vượt giới hạn khiến SPF trả lỗi vĩnh viễn (permerror) và có thể bị coi như không có SPF.",
          technical: "Đếm các cơ chế include/a/mx/ptr/exists/redirect ở cấp đầu tiên; include lồng nhau có thể làm con số thực tế còn lớn hơn.", evidence: [truncate(d.spf, 200)],
          remediation: { summary: "Gộp/đơn giản hoá các include hoặc dùng dịch vụ “SPF flattening”.", snippets: [] } }));
      }
      if ((d.spfRecords ?? 1) > 1) {
        problems.push(makeFinding({ ruleId: this.id, key: "spf-multiple", title: "Có nhiều hơn một bản ghi SPF", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: null, references: refs,
          summary: `Tìm thấy ${d.spfRecords} bản ghi SPF; chỉ được phép có một.`, explanation: "Theo RFC 7208, nhiều bản ghi SPF làm toàn bộ kiểm tra SPF lỗi (permerror).",
          evidence: [`${d.spfRecords} bản ghi v=spf1 tại ${dm}`], remediation: { summary: "Gộp mọi cơ chế vào một bản ghi SPF duy nhất.", snippets: [] } }));
      }
      if (problems.length) out.push(...problems);
      else out.push(pass({ ruleId: this.id, title: "Bản ghi SPF được công bố", category: CAT, summary: "SPF có mặt, đúng cú pháp và có kết thúc chặt chẽ.", explanation: "Máy chủ nhận thư có thể xác minh nguồn gửi hợp lệ.", evidence: [truncate(d.spf, 200)] }));
    }

    // ---- CAA, DNSSEC, MTA-STS
    if (d.caa !== null && d.caa.length === 0) {
      out.push(makeFinding({ ruleId: this.id, key: "caa", title: "Chưa có bản ghi CAA", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null,
        summary: "Không có bản ghi CAA giới hạn đơn vị nào được cấp chứng chỉ cho tên miền này.", explanation: "CAA là lớp bảo vệ tuỳ chọn chống việc cấp chứng chỉ nhầm.", evidence: [`CAA ${dm}: (không có)`],
        remediation: { summary: "Có thể thêm bản ghi CAA cho nhà cấp chứng chỉ bạn dùng.", snippets: [{ platform: "generic", label: `CAA ${dm}`, language: "text", code: '0 issue "letsencrypt.org"' }] } }));
    }
    if (d.dnssec === false) {
      out.push(makeFinding({ ruleId: this.id, key: "dnssec", title: "Chưa bật DNSSEC", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null,
        references: [{ title: "Cloudflare: What is DNSSEC?", url: "https://www.cloudflare.com/learning/dns/dnssec/how-dnssec-works/" }],
        summary: `Bộ phân giải không xác thực được chữ ký DNSSEC cho ${dm}.`, explanation: "DNSSEC chống việc giả mạo kết quả DNS (DNS spoofing/cache poisoning), tức là dẫn khách tới máy chủ giả. Là lớp tăng cường tuỳ chọn, không phải ai cũng cần.",
        technical: "Cờ AD (Authenticated Data) = false từ bộ phân giải công cộng của Cloudflare.", evidence: [`${dm}: AD=false`],
        remediation: { summary: "Bật DNSSEC tại nhà đăng ký tên miền hoặc nhà cung cấp DNS.", steps: ["Cloudflare DNS: DNS → Settings → Enable DNSSEC, sau đó thêm bản ghi DS tại nhà đăng ký tên miền.", "Nhiều nhà đăng ký Việt Nam hỗ trợ DS record trong trang quản lý tên miền — kiểm tra mục “DNSSEC”."], snippets: [] } }));
    } else if (d.dnssec === true) {
      out.push(pass({ ruleId: this.id, title: "DNSSEC được bật", category: CAT, summary: "Kết quả DNS của tên miền được xác thực bằng DNSSEC.", explanation: "Khó giả mạo kết quả DNS để chuyển hướng khách tới máy chủ giả.", evidence: [`${dm}: AD=true`] }));
    }
    if (d.mtaSts === false && d.mx && d.mx.length > 0) {
      out.push(makeFinding({ ruleId: this.id, key: "mta-sts", title: "Chưa bật MTA-STS", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: null,
        references: [{ title: "RFC 8461: MTA-STS", url: "https://www.rfc-editor.org/rfc/rfc8461" }],
        summary: "Tên miền có nhận email (có bản ghi MX) nhưng chưa có chính sách MTA-STS.", explanation: "MTA-STS buộc các máy chủ email gửi tới bạn phải dùng TLS, tránh việc thư bị hạ cấp xuống dạng không mã hoá.",
        evidence: [`MX: ${d.mx.slice(0, 3).join(", ")}`, `TXT _mta-sts.${dm}: (không có)`],
        remediation: { summary: "Công bố bản ghi TXT _mta-sts và file chính sách tại https://mta-sts.<tên-miền>/.well-known/mta-sts.txt.", snippets: [] } }));
    }
    // ---- dự phòng máy chủ tên
    if (d.ns && d.ns.length === 1) {
      out.push(makeFinding({ ruleId: this.id, key: "ns-single", title: "Chỉ có một máy chủ tên (NS)", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: null,
        summary: `${dm} chỉ khai báo một máy chủ tên: ${d.ns[0]}.`, explanation: "Nếu máy chủ tên duy nhất ngừng hoạt động, toàn bộ website và email của tên miền sẽ không phân giải được. RFC 1034 khuyến nghị ít nhất hai máy chủ tên độc lập.",
        evidence: [`NS ${dm}: ${d.ns[0]}`], remediation: { summary: "Thêm ít nhất một máy chủ tên thứ hai (tốt nhất ở nhà cung cấp/mạng khác).", snippets: [] } }));
    }
    return out;
  },
};

const authSurface: Rule = {
  id: "config.auth-surface",
  title: "Cấu hình xác thực quan sát được từ bên ngoài",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const hints: string[] = [];
    const joined = obs.technologies.join(",");
    if (/Supabase/.test(joined)) hints.push("Supabase (hãy kiểm tra Row Level Security trên mọi bảng)");
    if (/Firebase/.test(joined)) hints.push("Firebase (hãy kiểm tra Security Rules của Firestore/Storage/RTDB)");
    const cookieNames = [...(obs.https?.chain ?? []).flatMap((h) => (Array.isArray(h.headers["set-cookie"]) ? h.headers["set-cookie"] : h.headers["set-cookie"] ? [h.headers["set-cookie"] as string] : []))].map((c) => c.split("=")[0]!);
    if (cookieNames.some((n) => /next-auth|authjs/i.test(n))) hints.push("Cookie phiên Auth.js / NextAuth");
    if (cookieNames.some((n) => /^sb-.*-auth-token/i.test(n))) hints.push("Cookie phiên Supabase Auth");
    if (obs.html.hasPasswordInput) hints.push("Trang này có form đăng nhập bằng mật khẩu");
    if (hints.length === 0) return [];
    return [makeFinding({ ruleId: this.id, title: "Hệ thống xác thực có thể quan sát từ bên ngoài", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: obs.page.finalUrl,
      summary: `Quan sát được: ${hints.join("; ")}.`, explanation: "Điều này là bình thường, không phải lỗ hổng. Nó chỉ cho bạn biết cần kiểm tra lại kiểm soát truy cập ở đâu, vì kẻ tấn công cũng thấy cùng các dấu hiệu.",
      evidence: hints, remediation: null })];
  },
};

export const configRules: Rule[] = [serverDisclosure, techFingerprint, redirects, dnsRule, authSurface];
