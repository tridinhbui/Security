import type { Metadata } from "next";
import Link from "next/link";
import { CONFIDENCE_FACTOR, scoringTable } from "@/lib/guidance";
import { CATEGORY_LABEL, CONFIDENCE_LABEL } from "@/lib/i18n";
import { SEV_COLOR } from "@/lib/format";
import { PLAIN_TITLES } from "@/lib/beginner";
import { ALL_RULES } from "@/lib/scanner/rules";
import { CATEGORIES } from "@/lib/scanner/types";

export const metadata: Metadata = {
  title: "Phương pháp chấm điểm & danh sách kiểm tra",
  description: "VibeSec chấm điểm thế nào, kiểm tra những gì, và những gì tuyệt đối không làm.",
};

export default function MethodPage() {
  return (
    <div className="container-x max-w-3xl py-12 sm:py-16">
      <h1 className="text-3xl font-semibold tracking-tight">Phương pháp chấm điểm &amp; danh sách kiểm tra</h1>
      <p className="mt-3 text-muted">Mọi kết luận của VibeSec đều đến từ các luật cố định, có thể tái lập — không dùng AI để “đoán” lỗ hổng. Cùng một website ở cùng một trạng thái sẽ luôn cho cùng một kết quả.</p>

      <section className="mt-12" aria-labelledby="diem">
        <h2 id="diem" className="text-xl font-semibold tracking-tight">Cách tính điểm</h2>
        <div className="mt-3 space-y-3 text-[15px] text-muted leading-relaxed">
          <p>Website bắt đầu với 100 điểm. Mỗi phát hiện ở trạng thái <strong className="text-fg font-medium">“Có vấn đề”</strong> bị trừ <strong className="text-fg font-medium">trọng số mức độ × hệ số độ tin cậy</strong>. Kết quả “Đạt”, “Ghi chú” và “Chưa kiểm tra được” không bao giờ làm giảm điểm.</p>
          <ul className="flex flex-wrap gap-x-6 gap-y-1">
            {scoringTable().map((r) => <li key={r.severity}><span className={SEV_COLOR[r.severity]}>{r.label}</span>: <span className="num text-fg">−{r.weight}</span></li>)}
          </ul>
          <p>Hệ số độ tin cậy: cao <span className="num text-fg">×{CONFIDENCE_FACTOR.high}</span>, {CONFIDENCE_LABEL.medium} <span className="num text-fg">×{CONFIDENCE_FACTOR.medium}</span>, thấp <span className="num text-fg">×{CONFIDENCE_FACTOR.low}</span>. Những phát hiện dựa trên suy đoán (heuristic) luôn có độ tin cậy thấp hơn và bị trừ ít hơn.</p>
          <p><strong className="text-fg font-medium">Chỉ gán “Nghiêm trọng” hoặc “Cao” khi bằng chứng chứng minh điều đó</strong> — ví dụ một khoá bí mật còn nguyên định dạng nhà cung cấp, hoặc form mật khẩu gửi qua HTTP thuần. Phát hiện dựa trên suy luận không bao giờ vượt mức Trung bình.</p>
          <p>Để một lỗi nặng không bị che bởi nhiều mục nhỏ đạt, có trần điểm: có vấn đề <em>Nghiêm trọng</em> thì tối đa 59 điểm, có vấn đề <em>Cao</em> thì tối đa 79 điểm. Hạng: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F dưới 60.</p>
          <p className="border-l-2 border-line-strong pl-3">Điểm số là đánh giá cấu hình <em>từ bên ngoài</em>. Điểm cao không chứng minh website an toàn, và điểm thấp không chứng minh website đã bị xâm nhập.</p>
        </div>
      </section>

      <section className="mt-12" aria-labelledby="khong-lam">
        <h2 id="khong-lam" className="text-xl font-semibold tracking-tight">Những gì VibeSec tuyệt đối không làm</h2>
        <ul className="mt-3 space-y-2 text-[15px] text-muted">
          {["Không đoán mật khẩu, không vượt qua xác thực, không thử SQL injection, XSS, command injection hay bất kỳ payload khai thác nào.",
            "Không fuzzing, không quét cổng, không dò các đường dẫn nhạy cảm như /.env hay /.git.",
            "Không truy cập mạng nội bộ, localhost hay metadata đám mây: các địa chỉ này bị chặn ở nhiều lớp (kiểm tra URL, kiểm tra DNS, ghim địa chỉ IP khi kết nối, kiểm tra lại mỗi lần chuyển hướng).",
            "Không crawl cả website: chỉ trang bạn nhập, một số ít script cùng origin và vài tệp công khai cố định (tối đa 34 request mỗi lần quét).",
            "Không lưu nội dung phản hồi. Khoá bí mật nếu phát hiện được che ngay lúc nhận diện, giá trị cookie bị loại bỏ, header gốc được mã hoá khi lưu."].map((t) => <li key={t} className="flex gap-3"><span className="text-ok" aria-hidden>✓</span>{t}</li>)}
        </ul>
      </section>

      <section className="mt-12" aria-labelledby="ds">
        <h2 id="ds" className="text-xl font-semibold tracking-tight">Danh sách {ALL_RULES.length} kiểm tra</h2>
        <p className="mt-2 text-sm text-muted">Danh sách này được sinh trực tiếp từ bộ luật đang chạy, nên luôn đúng với thực tế.</p>
        <div className="mt-6 space-y-8">
          {CATEGORIES.map((c) => (
            <div key={c}>
              <h3 className="font-medium">{CATEGORY_LABEL[c]}</h3>
              <ul className="mt-2 divide-y divide-line border-y border-line">
                {ALL_RULES.filter((r) => r.category === c).map((r) => (
                  <li key={r.id} className="py-2.5 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1 text-sm">
                    <span>{PLAIN_TITLES[r.id] ?? r.title}</span>
                    <span className="font-mono text-xs text-faint">{r.id}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <p className="mt-12 text-sm"><Link href="/" className="underline underline-offset-4 text-muted hover:text-fg">← Quay lại trang chủ</Link></p>
    </div>
  );
}
