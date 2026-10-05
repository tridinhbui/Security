import type { Finding, Rule } from "../types";
import { makeFinding, MDN, pass, truncate } from "../util";

const CAT = "Browser Security" as const;
const ACTIVE_TAGS = new Set(["script", "link", "iframe", "object", "embed"]);
const SRI_CDN_HOSTS = /(^|\.)(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|cdn\.bootcss\.com)$/;

const mixedContent: Rule = {
  id: "browser.mixed-content",
  title: "Không có nội dung hỗn hợp (mixed content)",
  category: CAT,
  run(obs) {
    if (!obs.pageIsHttps || !obs.html || !obs.page) return [];
    const insecure = obs.html.resources.filter((r) => r.url.startsWith("http://"));
    const url = obs.page.finalUrl;
    const refs = [MDN("Web/Security/Mixed_content", "MDN: Mixed content")];
    if (insecure.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Trang tải toàn bộ tài nguyên qua HTTPS.", explanation: "Không có phần nào của trang có thể bị can thiệp trên đường truyền.", evidence: [`Đã kiểm tra ${obs.html.resources.length} tham chiếu tài nguyên`], references: refs })];
    }
    const active = insecure.filter((r) => ACTIVE_TAGS.has(r.tag));
    const out: Finding[] = [];
    if (active.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "active", title: "Trang tải script hoặc CSS qua HTTP", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `${active.length} tài nguyên script/CSS/frame được gọi bằng http:// trên một trang HTTPS.`,
        explanation: "Trình duyệt chặn chúng nên một phần website có thể đang hỏng — và nếu có thứ lọt qua, kẻ tấn công có thể thay thế để chạy mã trên trang của bạn.",
        technical: "Active mixed content (script/stylesheet/iframe/object/embed qua http://).",
        evidence: active.slice(0, 8).map((r) => `<${r.tag} ${r.attr}="${truncate(r.url, 160)}">`),
        remediation: { summary: "Đổi mọi tham chiếu http:// sang https:// (hoặc URL tương đối). Nếu bên kia không có HTTPS, hãy tự lưu trữ file hoặc bỏ nó đi.", steps: ["Thêm directive sau vào CSP để tự nâng cấp các request sót: upgrade-insecure-requests"], snippets: [] },
      }));
    }
    const passive = insecure.filter((r) => !ACTIVE_TAGS.has(r.tag));
    if (passive.length) {
      out.push(makeFinding({
        ruleId: this.id, key: "passive", title: "Trang tải ảnh hoặc media qua HTTP", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `${passive.length} tài nguyên ảnh/media được gọi bằng http:// trên một trang HTTPS.`,
        explanation: "Trình duyệt hiện cảnh báo “không hoàn toàn an toàn” hoặc tự nâng cấp chúng, và nội dung có thể bị thay thế bởi người trên cùng mạng.",
        technical: "Passive mixed content.", evidence: passive.slice(0, 8).map((r) => `<${r.tag} ${r.attr}="${truncate(r.url, 160)}">`),
        remediation: { summary: "Dùng URL https:// cho mọi ảnh và media.", snippets: [] },
      }));
    }
    return out;
  },
};

const externalResources: Rule = {
  id: "browser.third-party-integrity",
  title: "Script CDN bên thứ ba có Subresource Integrity",
  category: CAT,
  run(obs) {
    if (!obs.html || !obs.page) return [];
    const url = obs.page.finalUrl;
    const missing: string[] = [];
    for (const s of obs.html.scripts) {
      if (!s.url || s.sameOrigin || s.integrity) continue;
      const host = new URL(s.url).hostname;
      if (SRI_CDN_HOSTS.test(host)) missing.push(s.url);
    }
    for (const c of obs.html.stylesheets) {
      if (c.sameOrigin || c.integrity) continue;
      if (SRI_CDN_HOSTS.test(new URL(c.href).hostname)) missing.push(c.href);
    }
    if (missing.length === 0) return [];
    return [makeFinding({
      ruleId: this.id, title: "File từ CDN được tải mà không kiểm tra tính toàn vẹn", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: url,
      references: [MDN("Web/Security/Subresource_Integrity", "MDN: Subresource Integrity")],
      summary: `${missing.length} file từ CDN công cộng được tải mà không có thuộc tính integrity.`,
      explanation: "Nếu CDN (hoặc gói trên đó) bị xâm nhập, kẻ tấn công có thể sửa file và chạy mã trên website của bạn. Mã băm integrity khiến trình duyệt từ chối file đã bị sửa.",
      technical: "<script>/<link rel=stylesheet> cross-origin từ CDN tĩnh không có integrity=\"sha384-…\".",
      evidence: missing.slice(0, 8).map((m) => truncate(m, 200)),
      remediation: { summary: 'Thêm integrity="sha384-…" và crossorigin="anonymous" vào từng thẻ, hoặc tự lưu trữ file.', steps: ["Tạo mã băm bằng: openssl dgst -sha384 -binary file.js | openssl base64 -A  (hoặc dùng srihash.org)", "Ghim chính xác phiên bản trong URL để mã băm luôn đúng."], snippets: [] },
    })];
  },
};

const cors: Rule = {
  id: "browser.cors",
  title: "Cấu hình CORS",
  category: CAT,
  run(obs) {
    const c = obs.cors;
    if (!c || c.status === null) return [];
    const url = obs.page?.finalUrl ?? obs.target.url;
    const refs = [MDN("Web/HTTP/Guides/CORS", "MDN: CORS"), { title: "PortSwigger: CORS", url: "https://portswigger.net/web-security/cors" }];
    const ev = [`Origin gửi đi: ${c.testedOrigin}`, `Access-Control-Allow-Origin: ${c.acao ?? "(không có)"}`, `Access-Control-Allow-Credentials: ${c.acac ?? "(không có)"}`];
    const creds = c.acac?.toLowerCase() === "true";
    if (!c.acao) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Website không cấp quyền truy cập cross-origin cho các origin lạ.", explanation: "Website khác không thể đọc phản hồi của website này từ trình duyệt của khách.", evidence: ev, references: refs })];
    if (c.acao === c.testedOrigin) {
      return [makeFinding({
        ruleId: this.id, title: creds ? "CORS phản chiếu mọi origin và cho phép gửi kèm thông tin đăng nhập" : "CORS phản chiếu mọi origin", category: CAT,
        severity: creds ? "high" : "low", confidence: "medium", status: "fail", affectedUrl: url, references: refs,
        summary: creds ? "Máy chủ lặp lại nguyên origin mà chúng tôi gửi và đồng thời cho phép kèm cookie." : "Máy chủ lặp lại nguyên origin mà chúng tôi gửi.",
        explanation: creds ? "Bất kỳ website nào mà người dùng đang đăng nhập mở ra đều có thể đọc phản hồi của website này thay mặt họ — kể cả dữ liệu tài khoản riêng tư — nếu quy tắc này áp dụng cho các endpoint cần xác thực." : "Website bất kỳ có thể đọc phản hồi này trong trình duyệt. Không sao với nội dung công khai nhưng nguy hiểm nếu cùng quy tắc áp dụng cho API riêng tư.",
        technical: "Phản chiếu origin (một origin ngẫu nhiên, chưa đăng ký, vẫn được chấp nhận).", evidence: ev,
        remediation: { summary: "So sánh header Origin với danh sách cho phép tường minh và chỉ phản chiếu khi khớp. Không bao giờ kết hợp CORS có credentials với origin phản chiếu hoặc wildcard.", steps: ["Thêm Vary: Origin bất cứ khi nào origin được phép phụ thuộc vào request.", "Hãy kiểm tra cả các endpoint API của bạn — chúng tôi chỉ thử trang bạn nhập."], snippets: [] },
      })];
    }
    if (c.acao === "null") {
      return [makeFinding({ ruleId: this.id, title: "CORS cho phép origin “null”", category: CAT, severity: creds ? "high" : "medium", confidence: "medium", status: "fail", affectedUrl: url, references: refs,
        summary: "Đã đặt Access-Control-Allow-Origin: null.", explanation: "iframe sandbox và file cục bộ gửi Origin: null nên kẻ tấn công dễ dàng tạo ra nó và đọc được phản hồi.", evidence: ev,
        remediation: { summary: "Bỏ Access-Control-Allow-Origin: null và liệt kê tường minh các origin tin cậy.", snippets: [] } })];
    }
    if (c.acao === "*") {
      if (creds) {
        return [makeFinding({ ruleId: this.id, title: "CORS kết hợp wildcard với credentials", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
          summary: "Access-Control-Allow-Origin: * cùng Allow-Credentials: true là tổ hợp không hợp lệ.", explanation: "Trình duyệt từ chối tổ hợp này, nên request cross-origin cần cookie sẽ âm thầm thất bại — thường là dấu hiệu cấu hình sai.", evidence: ev,
          remediation: { summary: "Bỏ credentials, hoặc thay * bằng một origin tin cậy cụ thể.", snippets: [] } })];
      }
      return [makeFinding({ ruleId: this.id, title: "CORS cho phép mọi origin (công khai)", category: CAT, severity: "low", confidence: "low", status: "fail", affectedUrl: url, references: refs,
        summary: "Website bất kỳ có thể đọc phản hồi này (Access-Control-Allow-Origin: *).", explanation: "Bình thường với tài nguyên công khai và API mở, nhưng hãy chắc chắn không có dữ liệu riêng tư nào được phục vụ kèm header này.", evidence: ev,
        remediation: { summary: "Chỉ giữ * cho tài nguyên thật sự công khai.", snippets: [] } })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "CORS được giới hạn cho một origin cụ thể thay vì phản chiếu origin của chúng tôi.", explanation: "Website lạ không đọc được phản hồi.", evidence: ev, references: refs })];
  },
};

export const browserRules: Rule[] = [mixedContent, externalResources, cors];
