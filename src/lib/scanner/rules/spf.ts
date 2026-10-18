/**
 * MỘT bộ phân tích SPF dùng chung cho config.dns-email-security và adv.spf-deep, để hai luật không bao giờ kết luận ngược nhau
 * (trước đây “~all” được luật cơ bản coi là chặt chẽ còn luật sâu lại báo yếu).
 *
 * Quy ước (RFC 7208):
 *  - "-all": từ chối nguồn khác (chặt nhất) · "~all": softfail — chấp nhận được, nhất là khi có DMARC thực thi;
 *  - "?all" hoặc KHÔNG có "all" (và không có redirect=): kết quả mặc định là trung lập → không chặn được thư giả;
 *  - "+all" hoặc "all" trơn: mọi máy chủ đều hợp lệ → vô hiệu hoá SPF;
 *  - "redirect=": phần kết thúc nằm ở bản ghi khác, không đánh giá được từ đây.
 */
export type SpfAll = "-" | "~" | "?" | "+" | "none" | "redirect";
export interface SpfAnalysis { all: SpfAll; lookups: number; usesPtr: boolean }

export function spfLookupCount(spf: string): number {
  return (spf.match(/\b(include:|a(?=[:/\s]|$)|mx(?=[:/\s]|$)|ptr|exists:|redirect=)/gi) ?? []).length;
}

export function analyzeSpf(spf: string): SpfAnalysis {
  const m = /(?:^|\s)([+~?-]?)all\b/i.exec(spf);
  const all: SpfAll = m ? ((m[1] || "+") as SpfAll) : /(?:^|\s)redirect=/i.test(spf) ? "redirect" : "none";
  return { all, lookups: spfLookupCount(spf), usesPtr: /(?:^|\s)[+~?-]?ptr\b/i.test(spf) };
}

export interface SpfIssue { key: "spf-plus-all" | "spf-neutral" | "spf-no-all" | "spf-lookups" | "spf-ptr"; severity: "medium" | "low"; text: string }
/** Các vấn đề SPF (đã thống nhất mức độ). "~all" và "-all" KHÔNG phải vấn đề. */
export function spfIssues(a: SpfAnalysis): SpfIssue[] {
  const out: SpfIssue[] = [];
  if (a.all === "+") out.push({ key: "spf-plus-all", severity: "medium", text: "SPF kết thúc bằng +all (hoặc all không kèm dấu): mọi máy chủ trên Internet đều được coi là hợp lệ, SPF mất tác dụng." });
  else if (a.all === "?") out.push({ key: "spf-neutral", severity: "low", text: "SPF kết thúc bằng ?all (trung lập): không khẳng định thư từ nguồn khác là giả, nên không giúp chặn thư mạo danh." });
  else if (a.all === "none") out.push({ key: "spf-no-all", severity: "low", text: "SPF không có phần kết thúc “all” (mặc định là trung lập): thư từ nguồn không liệt kê không bị đánh dấu là giả." });
  if (a.lookups > 10) out.push({ key: "spf-lookups", severity: "low", text: `Bản ghi SPF kích hoạt khoảng ${a.lookups} truy vấn DNS (giới hạn của RFC 7208 là 10): vượt giới hạn thì SPF trả lỗi vĩnh viễn (permerror).` });
  if (a.usesPtr) out.push({ key: "spf-ptr", severity: "low", text: "SPF dùng cơ chế ptr: RFC 7208 khuyến cáo không dùng (chậm, không đáng tin)." });
  return out;
}
