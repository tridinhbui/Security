import { headerFix, httpsRedirectFix, RECOMMENDED } from "../remediation";
import type { Finding, Observations, Rule } from "../types";
import { header, headerEvidence, makeFinding, MDN, pass } from "../util";

const CAT = "Transport Security" as const;

const CERT_LABELS: Record<string, string> = {
  CERT_HAS_EXPIRED: "chứng chỉ đã hết hạn",
  DEPTH_ZERO_SELF_SIGNED_CERT: "chứng chỉ là loại tự ký (self-signed)",
  SELF_SIGNED_CERT_IN_CHAIN: "chuỗi chứng chỉ chứa một chứng chỉ tự ký",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "chuỗi chứng chỉ không đầy đủ hoặc không được tin cậy",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "đơn vị cấp chứng chỉ không được tin cậy",
  ERR_TLS_CERT_ALTNAME_INVALID: "chứng chỉ không khớp với tên miền này",
  CERT_NOT_YET_VALID: "chứng chỉ chưa có hiệu lực",
  CERT_REVOKED: "chứng chỉ đã bị thu hồi",
};

/** Mã lỗi cho biết chắc chắn là "không có HTTPS" (khác với lỗi mạng chập chờn). */
const NO_TLS_CODES = new Set(["ECONNREFUSED", "EPROTO", "ERR_SSL_WRONG_VERSION_NUMBER", "ERR_SSL_PROTOCOL_ERROR"]);

const httpsAvailable: Rule = {
  id: "tls.https-available",
  title: "HTTPS hoạt động với chứng chỉ hợp lệ",
  category: CAT,
  run(obs) {
    const h = obs.https;
    if (!h) return [];
    const url = h.requestedUrl;
    const refs = [MDN("Web/Security/Transport_Layer_Security", "MDN: Transport Layer Security")];

    if (h.certError) {
      const why = CERT_LABELS[h.certError.code] ?? "không xác minh được chứng chỉ";
      return [
        makeFinding({
          ruleId: this.id, title: "Chứng chỉ HTTPS không được tin cậy", category: CAT, severity: "high", confidence: "high",
          status: "fail", affectedUrl: url, references: refs,
          summary: `Trình duyệt sẽ hiện cảnh báo toàn màn hình trước khi vào website vì ${why}.`,
          explanation: "Khách truy cập thấy cảnh báo bảo mật và đa số sẽ rời đi. Kẻ xấu cùng mạng cũng có thể mạo danh website của bạn nếu người dùng bấm bỏ qua cảnh báo.",
          technical: `Xác minh TLS thất bại với mã ${h.certError.code}.`,
          evidence: [`GET ${url} → lỗi TLS ${h.certError.code}`, ...(h.tls?.subject ? [`Chủ thể chứng chỉ: ${h.tls.subject}`] : []), ...(h.tls?.validTo ? [`Có hiệu lực đến: ${h.tls.validTo}`] : [])],
          remediation: {
            summary: "Cài chứng chỉ hợp lệ, được tin cậy công khai, khớp chính xác tên miền và có đủ chuỗi chứng chỉ trung gian.",
            steps: ["Hầu hết nền tảng (Vercel, Netlify, Cloudflare) cấp chứng chỉ miễn phí tự động — hãy kiểm tra tên miền đã được gắn đúng.", "Với máy chủ riêng, dùng Let's Encrypt (certbot) và cấu hình file fullchain chứ không chỉ chứng chỉ lá.", "Đảm bảo chứng chỉ liệt kê đúng tên miền này trong Subject Alternative Names."],
            snippets: [],
          },
        }),
      ];
    }
    if (h.error) {
      if (NO_TLS_CODES.has(h.error.code)) {
        return [
          makeFinding({
            ruleId: this.id, title: "Website không hỗ trợ HTTPS", category: CAT, severity: "high", confidence: "high", status: "fail",
            affectedUrl: url, references: refs,
            summary: "Website này không chấp nhận kết nối HTTPS.",
            explanation: "Không có HTTPS, mọi dữ liệu người dùng gửi và nhận — kể cả mật khẩu — đều có thể bị đọc hoặc sửa bởi bất kỳ ai trên đường truyền.",
            technical: `Kết nối tới cổng 443 thất bại: ${h.error.code}.`,
            evidence: [`GET ${url} → ${h.error.code}`],
            remediation: { summary: "Bật HTTPS trên hosting hoặc CDN và lấy chứng chỉ miễn phí (Let's Encrypt hoặc chứng chỉ tự động của nền tảng).", snippets: [] },
          }),
        ];
      }
      return [
        makeFinding({
          ruleId: this.id, title: "Chưa hoàn tất kiểm tra HTTPS", category: CAT, severity: "info", confidence: "low", status: "unknown",
          affectedUrl: url, summary: "Trong lần quét này chúng tôi không kết nối ổn định qua HTTPS nên các kiểm tra đường truyền chưa đầy đủ.",
          explanation: "Thường do mạng chập chờn, bị giới hạn tốc độ hoặc máy chủ chậm. Hãy thử quét lại.",
          evidence: [`GET ${url} → ${h.error.code}: ${h.error.message}`], remediation: null,
        }),
      ];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "HTTPS hoạt động và chứng chỉ được tin cậy.", explanation: "Khách truy cập có kết nối mã hoá tới đúng website thật.", evidence: [`TLS: ${h.tls?.protocol ?? "?"}, nhà cấp: ${h.tls?.issuer ?? "?"}`], references: refs })];
  },
};

const certExpiry: Rule = {
  id: "tls.certificate-expiry",
  title: "Chứng chỉ chưa sắp hết hạn",
  category: CAT,
  run(obs) {
    const t = obs.https?.tls;
    if (!t || t.daysRemaining === undefined || obs.https?.certError) return [];
    const url = obs.https!.requestedUrl;
    const evidence = [`Có hiệu lực đến ${t.validTo} (còn ${t.daysRemaining} ngày)`];
    if (t.daysRemaining < 0) return []; // được báo ở mục chứng chỉ không tin cậy
    if (t.daysRemaining < 14) {
      return [makeFinding({
        ruleId: this.id, title: "Chứng chỉ sắp hết hạn", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
        summary: `Chứng chỉ HTTPS sẽ hết hạn sau ${t.daysRemaining} ngày.`,
        explanation: "Khi hết hạn, mọi khách truy cập sẽ thấy cảnh báo bảo mật cho đến khi bạn gia hạn.",
        evidence, remediation: { summary: "Gia hạn chứng chỉ ngay và kiểm tra cơ chế tự động gia hạn (certbot timer, tự gia hạn của nền tảng) còn hoạt động.", snippets: [] },
      })];
    }
    if (t.daysRemaining < 30) {
      return [makeFinding({
        ruleId: this.id, title: "Chứng chỉ hết hạn trong vòng 30 ngày", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url,
        summary: `Chứng chỉ HTTPS sẽ hết hạn sau ${t.daysRemaining} ngày.`, explanation: "Cơ chế tự động thường gia hạn khi còn khoảng 30 ngày. Nếu chứng chỉ này chưa được gia hạn, có thể việc tự động gia hạn đang hỏng.",
        evidence, remediation: { summary: "Xác minh cơ chế tự động gia hạn đang chạy.", snippets: [] },
      })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `Chứng chỉ còn hiệu lực thêm ${t.daysRemaining} ngày.`, explanation: "Còn nhiều thời gian trước khi cần gia hạn.", evidence })];
  },
};

const certStrength: Rule = {
  id: "tls.certificate-strength",
  title: "Chứng chỉ dùng khoá đủ mạnh",
  category: CAT,
  run(obs) {
    const t = obs.https?.tls;
    if (!t || obs.https?.certError || !t.keyType) return [];
    const url = obs.https!.requestedUrl;
    const refs = [{ title: "CA/Browser Forum Baseline Requirements", url: "https://cabforum.org/working-groups/server/baseline-requirements/documents/" }];
    const desc = `${t.keyType.toUpperCase()}${t.keyBits ? ` ${t.keyBits} bit` : ""}${t.curve ? ` (${t.curve})` : ""}`;
    const evidence = [`Khoá công khai: ${desc}`, ...(t.validityDays ? [`Thời hạn chứng chỉ: ${t.validityDays} ngày`] : []), `Số chứng chỉ trong chuỗi: ${t.chainLength ?? "?"}`];
    const out: Finding[] = [];
    const weakRsa = t.keyType === "rsa" && (t.keyBits ?? 4096) < 2048;
    const weakEc = t.keyType === "ec" && (t.keyBits ?? 256) < 224;
    if (weakRsa || weakEc) {
      out.push(makeFinding({
        ruleId: this.id, key: "weak-key", title: "Chứng chỉ dùng khoá mật mã yếu", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `Khoá của chứng chỉ chỉ là ${desc}, thấp hơn mức tối thiểu hiện nay (RSA 2048 bit hoặc EC 256 bit).`,
        explanation: "Khoá ngắn có thể bị bẻ khoá bằng sức mạnh tính toán hiện đại, khi đó kẻ tấn công có thể giả mạo website hoặc giải mã lưu lượng.",
        evidence, remediation: { summary: "Tạo khoá mới (RSA 2048+ hoặc ECDSA P-256) rồi xin cấp lại chứng chỉ.", steps: ["Ví dụ: openssl ecparam -genkey -name prime256v1 -noout -out key.pem", "Nếu dùng Let's Encrypt/certbot: certbot renew --force-renewal --key-type ecdsa"], snippets: [] },
      }));
    }
    if ((t.validityDays ?? 0) > 398) {
      out.push(makeFinding({
        ruleId: this.id, key: "long-validity", title: "Chứng chỉ có thời hạn dài bất thường", category: CAT, severity: "low", confidence: "medium", status: "fail", affectedUrl: url, references: refs,
        summary: `Chứng chỉ có thời hạn ${t.validityDays} ngày, vượt quá mức tối đa 398 ngày mà trình duyệt chấp nhận cho chứng chỉ công khai.`,
        explanation: "Chứng chỉ công khai cấp sau tháng 9/2020 không được vượt 398 ngày. Chứng chỉ dài hơn có thể bị trình duyệt từ chối, và thời hạn càng dài thì khoá bị lộ càng lâu mới bị phát hiện.",
        evidence, remediation: { summary: "Dùng chứng chỉ có thời hạn ngắn và bật tự động gia hạn (Let's Encrypt: 90 ngày).", snippets: [] },
      }));
    }
    if (t.wildcard) {
      out.push(makeFinding({
        ruleId: this.id, key: "wildcard", title: "Chứng chỉ wildcard", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url,
        summary: `Chứng chỉ bao phủ mọi subdomain (${(t.altNames ?? []).filter((n) => n.startsWith("*.")).join(", ")}).`,
        explanation: "Thuận tiện nhưng nếu khoá riêng bị lộ ở một máy chủ bất kỳ thì kẻ xấu có thể mạo danh mọi subdomain. Hãy bảo vệ khoá riêng nghiêm ngặt hoặc dùng chứng chỉ riêng cho từng dịch vụ quan trọng.",
        evidence, remediation: null,
      }));
    }
    if (out.length === 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `Khoá ${desc}, thời hạn ${t.validityDays ?? "?"} ngày.`, explanation: "Độ dài khoá và thời hạn chứng chỉ đáp ứng khuyến nghị hiện nay.", evidence, references: refs })];
    }
    return out;
  },
};

const tlsProtocol: Rule = {
  id: "tls.protocol-version",
  title: "Chỉ chấp nhận phiên bản TLS hiện đại",
  category: CAT,
  run(obs) {
    const url = obs.https?.requestedUrl ?? null;
    const legacy = obs.legacyTls;
    const bad: string[] = [];
    if (legacy?.tls10) bad.push("TLS 1.0");
    if (legacy?.tls11) bad.push("TLS 1.1");
    const negotiated = obs.https?.tls?.protocol;
    if (negotiated === "TLSv1" || negotiated === "TLSv1.1") bad.push(negotiated.replace("TLSv", "TLS "));
    if (bad.length) {
      const uniq = [...new Set(bad)];
      return [makeFinding({
        ruleId: this.id, title: "Máy chủ vẫn chấp nhận phiên bản TLS đã lỗi thời", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
        references: [MDN("Web/Security/Transport_Layer_Security", "MDN: TLS")],
        summary: `Máy chủ vẫn chấp nhận ${uniq.join(" và ")} — các phiên bản đã bị loại bỏ.`,
        explanation: "Các phiên bản TLS cũ có điểm yếu đã biết. Trình duyệt hiện đại không còn dùng chúng nên tắt đi không ảnh hưởng người dùng mà còn loại bỏ nguy cơ bị ép hạ cấp (downgrade).",
        technical: `Bắt tay TLS giới hạn ở ${uniq.join("/")} đã thành công.`,
        evidence: uniq.map((v) => `Bắt tay ${v} thành công`),
        remediation: { summary: "Chỉ cho phép TLS 1.2 và TLS 1.3.", steps: ["Nginx: ssl_protocols TLSv1.2 TLSv1.3;", "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3", "Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2", "Nền tảng được quản lý (Vercel, Netlify) đã tự áp dụng mức này."], snippets: [] },
      })];
    }
    if (!negotiated) return [];
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `Kết nối thương lượng ${negotiated.replace("TLSv", "TLS ")}${legacy && legacy.tls10 === false && legacy.tls11 === false ? "; TLS 1.0/1.1 bị từ chối." : "."}`, explanation: "TLS hiện đại bảo vệ lưu lượng của khách truy cập.", evidence: [`Phiên bản thương lượng: ${negotiated}`, `Bộ mã hoá: ${obs.https?.tls?.cipher ?? "?"}`] })];
  },
};

const http2: Rule = {
  id: "tls.http2",
  title: "Hỗ trợ HTTP/2",
  category: CAT,
  run(obs) {
    const h2 = obs.legacyTls?.h2;
    if (h2 === undefined || h2 === null || !obs.https || obs.https.error) return [];
    const url = obs.https.requestedUrl;
    const refs = [MDN("Web/HTTP/Guides/Connection_management_in_HTTP_1.x", "MDN: Quản lý kết nối HTTP")];
    if (h2) return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Máy chủ hỗ trợ HTTP/2 (thương lượng qua ALPN).", explanation: "HTTP/2 tải trang nhanh hơn và là điều kiện của nhiều tối ưu hiện đại.", evidence: ["ALPN: h2"], references: refs })];
    return [makeFinding({
      ruleId: this.id, title: "Chưa bật HTTP/2", category: CAT, severity: "info", confidence: "high", status: "info", affectedUrl: url, references: refs,
      summary: "Máy chủ chỉ trả lời HTTP/1.1, chưa thương lượng được HTTP/2.",
      explanation: "Không phải lỗ hổng bảo mật, nhưng HTTP/2 nhanh hơn, giảm thời gian tải và hầu như không có chi phí.",
      evidence: ["ALPN đã đề nghị: h2, http/1.1 — máy chủ chọn: http/1.1"],
      remediation: {
        summary: "Bật HTTP/2 trên máy chủ hoặc CDN.",
        steps: obs.platforms.includes("nginx") ? ["Nginx: trong khối server thêm “http2 on;” (hoặc “listen 443 ssl http2;” ở bản cũ)."] : obs.platforms.includes("apache") ? ["Apache: bật mô-đun http2 và thêm “Protocols h2 http/1.1”."] : ["Hầu hết CDN/nền tảng (Cloudflare, Vercel, Netlify) bật HTTP/2 mặc định — kiểm tra cấu hình nếu bạn đang tự vận hành máy chủ."],
        snippets: [],
      },
    })];
  },
};

const httpRedirect: Rule = {
  id: "tls.http-to-https-redirect",
  title: "HTTP được chuyển hướng sang HTTPS",
  category: CAT,
  run(obs) {
    const h = obs.http;
    if (!h) return [];
    const url = h.requestedUrl;
    const httpsOk = obs.https && !obs.https.error && obs.https.status !== null;
    if (h.error) {
      if (["ECONNREFUSED", "ETIMEDOUT"].includes(h.error.code)) {
        return [makeFinding({ ruleId: this.id, title: "Cổng 80 (HTTP) đóng", category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: url,
          summary: "Website không trả lời trên HTTP thuần.", explanation: "Không sao nếu mọi liên kết đều dùng https://, nhưng khách gõ tên miền trần có thể gặp lỗi thay vì được chuyển hướng.",
          evidence: [`GET ${url} → ${h.error.code}`], remediation: httpsRedirectFix(obs.platforms) })];
      }
      return [];
    }
    const finalIsHttps = h.finalUrl.startsWith("https://");
    if (finalIsHttps) {
      const first = h.chain[0];
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: "Request HTTP được chuyển hướng sang HTTPS.", explanation: "Khách bắt đầu bằng http:// sẽ được đưa sang phiên bản an toàn.", evidence: [`${first?.status} ${url} → ${h.finalUrl}`] })];
    }
    if (!httpsOk) return []; // HTTPS không hoạt động → báo ở tls.https-available
    return [makeFinding({
      ruleId: this.id, title: "HTTP không được chuyển hướng sang HTTPS", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url,
      references: [MDN("Web/Security/Transport_Layer_Security", "MDN: TLS")],
      summary: "Website vẫn phục vụ trên http:// thuần và không đưa khách sang phiên bản https://.",
      explanation: "Ai vào bằng HTTP — từ liên kết cũ hoặc gõ tên miền trần — vẫn không được mã hoá, có thể bị nghe lén hoặc bị chèn nội dung.",
      technical: `GET ${url} trả về ${h.status} mà không chuyển hướng sang https.`,
      evidence: [`GET ${url} → ${h.status}`, headerEvidence(h.headers, "location")], remediation: httpsRedirectFix(obs.platforms),
    })];
  },
};

const wwwConsistency: Rule = {
  id: "tls.www-consistency",
  title: "Phiên bản www / không-www cũng an toàn",
  category: CAT,
  run(obs) {
    const alt = obs.altHost;
    if (!alt || !alt.record) return [];
    const r = alt.record;
    const url = `https://${alt.host}/`;
    const refs = [MDN("Web/Security/Transport_Layer_Security", "MDN: TLS")];
    if (r.certError) {
      const why = CERT_LABELS[r.certError.code] ?? "chứng chỉ không hợp lệ";
      return [makeFinding({
        ruleId: this.id, title: `Chứng chỉ của ${alt.host} bị lỗi`, category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `Tên miền ${alt.host} (phiên bản ${alt.host.startsWith("www.") ? "có www" : "không có www"}) có lỗi chứng chỉ: ${why}.`,
        explanation: "Khách gõ thiếu hoặc thừa “www” sẽ gặp cảnh báo bảo mật đầy màn hình, rất dễ nghĩ website bị hỏng hoặc bị tấn công.",
        evidence: [`GET ${url} → lỗi TLS ${r.certError.code}`],
        remediation: { summary: `Cấp chứng chỉ bao gồm cả ${alt.host} hoặc chuyển hướng tên miền này về tên miền chính.`, steps: ["Cloudflare/Vercel/Netlify: thêm cả hai tên miền vào dự án và đặt một tên miền làm chính, tên còn lại tự chuyển hướng.", "certbot: certbot --nginx -d example.com -d www.example.com"], snippets: [] },
      })];
    }
    if (r.error) {
      if (r.error.blocked) return [];
      return [makeFinding({
        ruleId: this.id, title: `${alt.host} không phản hồi qua HTTPS`, category: CAT, severity: "info", confidence: "medium", status: "info", affectedUrl: url,
        summary: `Tên miền ${alt.host} có tồn tại nhưng không trả lời HTTPS (${r.error.code}).`,
        explanation: "Khách gõ thiếu hoặc thừa “www” sẽ không vào được website. Nên cấu hình để cả hai dạng cùng dẫn về một địa chỉ chính.",
        evidence: [`GET ${url} → ${r.error.code}`], remediation: { summary: `Trỏ ${alt.host} về cùng máy chủ và chuyển hướng 301 về tên miền chính.`, snippets: [] },
      })];
    }
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `${alt.host} cũng có chứng chỉ hợp lệ.`, explanation: "Khách gõ có hoặc không có “www” đều vào được trang an toàn.", evidence: [`GET ${url} → ${r.status}`], references: refs })];
  },
};

const hsts: Rule = {
  id: "tls.hsts",
  title: "HTTP Strict Transport Security (HSTS)",
  category: CAT,
  run(obs) {
    const h = obs.https;
    if (!h || h.error || h.status === null) return [];
    const url = h.finalUrl;
    const v = header(h.headers, "strict-transport-security");
    const refs = [MDN("Web/HTTP/Reference/Headers/Strict-Transport-Security", "MDN: Strict-Transport-Security")];
    if (!v) {
      return [makeFinding({
        ruleId: this.id, title: "Thiếu header HSTS", category: CAT, severity: "medium", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: "Website không yêu cầu trình duyệt luôn dùng HTTPS.",
        explanation: "Không có HSTS, request đầu tiên của khách vẫn có thể đi qua HTTP thuần, nơi kẻ tấn công trên mạng có thể chặn và gỡ bỏ lớp mã hoá (SSL stripping).",
        technical: "Phản hồi HTTPS không có header Strict-Transport-Security.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")],
        remediation: headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms),
      })];
    }
    const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(v);
    const age = maxAge ? Number(maxAge[1]) : NaN;
    if (Number.isNaN(age) || age === 0) return []; // được báo ở headers.broken
    if (age < 15_552_000) {
      return [makeFinding({
        ruleId: this.id, title: "Thời hạn HSTS quá ngắn", category: CAT, severity: "low", confidence: "high", status: "fail", affectedUrl: url, references: refs,
        summary: `HSTS đã bật nhưng chỉ kéo dài ${Math.round(age / 86400)} ngày.`, explanation: "Thời hạn ngắn khiến trình duyệt nhanh quên quy tắc “chỉ dùng HTTPS”, để lại khoảng hở cho khách quay lại.",
        evidence: [headerEvidence(h.headers, "strict-transport-security")], remediation: headerFix("Strict-Transport-Security", RECOMMENDED.hsts, obs.platforms, "Tăng max-age lên ít nhất 6 tháng (lý tưởng là 2 năm)."),
      })];
    }
    const notes = [!/includeSubDomains/i.test(v) ? "chưa có includeSubDomains" : "", !/preload/i.test(v) ? "chưa sẵn sàng preload" : ""].filter(Boolean);
    return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: url, summary: `HSTS đã bật trong ${Math.round(age / 86400)} ngày${notes.length ? ` (${notes.join(", ")})` : ""}.`, explanation: "Trình duyệt sẽ từ chối dùng HTTP thuần cho website này.", evidence: [headerEvidence(h.headers, "strict-transport-security")], references: refs })];
  },
};

const insecureLogin: Rule = {
  id: "tls.insecure-login-form",
  title: "Form đăng nhập được bảo vệ bằng HTTPS",
  category: CAT,
  run(obs: Observations): Finding[] {
    const html = obs.html;
    if (!html || !obs.page) return [];
    const out: Finding[] = [];
    const pageUrl = obs.page.finalUrl;
    const pwForms = html.forms.filter((f) => f.hasPassword);

    for (const f of pwForms) {
      if (f.action.startsWith("http://")) {
        out.push(makeFinding({
          ruleId: this.id, title: "Form mật khẩu gửi dữ liệu qua HTTP thuần", category: CAT, severity: "critical", confidence: "high", status: "fail",
          affectedUrl: pageUrl, key: `action:${new URL(f.action).host}${new URL(f.action).pathname}`,
          summary: "Một form có ô mật khẩu gửi dữ liệu tới địa chỉ http://.",
          explanation: "Mật khẩu được truyền không mã hoá, bất kỳ ai nằm giữa khách truy cập và máy chủ đều đọc được.",
          technical: `<form action="${f.action}"> chứa input[type=password].`, evidence: [`action của form: ${f.action}`, `trang: ${pageUrl}`],
          remediation: { summary: "Phục vụ trang và đích của form hoàn toàn qua HTTPS.", steps: ["Đổi action của form sang URL https:// (hoặc đường dẫn tương đối trên trang HTTPS).", "Chuyển hướng toàn bộ HTTP sang HTTPS và bật HSTS."], snippets: [] },
        }));
      }
      if (f.method === "get") {
        out.push(makeFinding({
          ruleId: this.id, title: "Form mật khẩu dùng phương thức GET", category: CAT, severity: "high", confidence: "high", status: "fail", affectedUrl: pageUrl, key: "method-get",
          summary: "Một form mật khẩu gửi dữ liệu bằng phương thức GET.",
          explanation: "GET đặt mật khẩu ngay trên URL, nơi nó lưu vào lịch sử trình duyệt, nhật ký máy chủ và header referrer.",
          technical: `<form method="get"> chứa input[type=password].`, evidence: [`action của form: ${f.action}`, "method: get"],
          remediation: { summary: 'Dùng method="post" cho mọi form mang thông tin đăng nhập.', snippets: [] },
        }));
      }
    }
    if (!obs.pageIsHttps && html.hasPasswordInput && !out.some((f) => f.fingerprint.includes("|action:"))) {
      out.push(makeFinding({
        ruleId: this.id, title: "Ô mật khẩu nằm trên trang HTTP thuần", category: CAT, severity: "high", confidence: "high", status: "fail", affectedUrl: pageUrl, key: "page-http",
        summary: "Một trang có ô mật khẩu được phục vụ qua HTTP không mã hoá.",
        explanation: "Trang có thể bị sửa trên đường truyền (để đánh cắp mật khẩu), và bản thân việc gửi form cũng không được mã hoá.",
        evidence: [`trang: ${pageUrl}`, "có input[type=password]"],
        remediation: httpsRedirectFix(obs.platforms),
      }));
    }
    if (out.length === 0 && pwForms.length > 0) {
      return [pass({ ruleId: this.id, title: this.title, category: CAT, affectedUrl: pageUrl, summary: "Form mật khẩu nằm trên HTTPS và gửi bằng POST.", explanation: "Thông tin đăng nhập được mã hoá khi truyền.", evidence: [`${pwForms.length} form mật khẩu`] })];
    }
    return out;
  },
};

export const transportRules: Rule[] = [httpsAvailable, certExpiry, certStrength, tlsProtocol, http2, httpRedirect, wwwConsistency, hsts, insecureLogin];
