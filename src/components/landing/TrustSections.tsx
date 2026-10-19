import Link from "next/link";
import { AnimatedNumber } from "@/components/motion/AnimatedNumber";
import { OWASP_MAP } from "@/lib/guidance";
import { ALL_RULES } from "@/lib/scanner/rules";
import { PASSIVE_SCORE_CEILING } from "@/lib/scanner/score";
import { OWASP_TOP10, standardsFor } from "@/lib/standards";
import { Reveal } from "./Reveal";

/** Mọi con số ở đây được TÍNH từ bộ luật đang chạy (không gõ tay), để trang giới thiệu không bao giờ hứa quá thực tế. */
function stats() {
  const cwe = new Set<number>(), asvs = new Set<string>(), wstg = new Set<string>(), owasp = new Set<string>();
  for (const r of ALL_RULES) {
    const s = standardsFor(r.id);
    s.cwe.forEach((c) => cwe.add(c)); s.asvs.forEach((c) => asvs.add(c)); s.wstg.forEach((c) => wstg.add(c));
    (OWASP_MAP[r.id] ?? []).forEach((o) => owasp.add(o.split(" – ")[0]!.slice(0, 3)));
  }
  return { rules: ALL_RULES.length, cwe: cwe.size, asvs: asvs.size, wstg: wstg.size, owasp: owasp.size };
}

const Arrow = () => <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg>;
const Ico = ({ d }: { d: string }) => <svg viewBox="0 0 24 24" className="size-6 text-fg" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d={d} /></svg>;




const REACH = { good: ["chip-ok", "Phủ tốt"], partial: ["chip-med", "Phủ một phần"], none: ["chip-info", "Không kiểm tra được"] } as const;


/** Ba trang quét dự án mới + nhờ chuyên gia. */
export function ProjectScans() {
  const cards = [
    { href: "/quet-ma-nguon", d: "m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16", t: "Quét mã nguồn", p: "Kết nối GitHub hoặc dán repo. Tìm khoá bí mật lỡ để lộ, file nhạy cảm, thư viện có CVE và code kém an toàn. Giá trị bí mật luôn được ẩn." },
    { href: "/quet-he-thong", d: "M4 4h16v6H4V4Zm0 10h16v6H4v-6ZM8 7h.01M8 17h.01", t: "Quét hệ thống", p: "Dán link website: tự nhận ra Supabase/Firebase và kiểm tra database, storage, đăng nhập có đang mở cho người lạ không. Chỉ đọc." },
    { href: "/truoc-ra-mat", d: "M12 3c3 2 5 5 5 9l-2 3H9l-2-3c0-4 2-7 5-9ZM9 15l-2 4 3-1M15 15l2 4-3-1M12 9v.01", t: "Quét trước ra mắt", p: "Gộp website, mã nguồn và hệ thống thành một kết luận: Sẵn sàng, Nên sửa trước, hay Chưa nên ra mắt. Sửa xong quét lại để xem Trước/Sau." },
  ];
  return (
    <section className="hairline" aria-labelledby="proj-h">
      <div className="container-x py-14">
        <Reveal><p className="eyebrow mb-3">từ website tới cả dự án</p><h2 id="proj-h" className="max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Không chỉ quét web. Kiểm tra cả dự án trước khi ra mắt.</h2></Reveal>
        <div className="mt-9 grid gap-4 md:grid-cols-3">
          {cards.map((c, i) => (
            <Reveal key={c.t} delay={i * 90}>
              <Link href={c.href} className="panel group flex h-full flex-col p-6 transition-[box-shadow,transform] duration-200 hover:-translate-y-0.5 hover:shadow-pop">
                <Ico d={c.d} /><h3 className="mt-4 text-[16px] font-semibold">{c.t}</h3><p className="mt-2 flex-1 text-[14.5px] leading-relaxed text-muted">{c.p}</p>
                <span className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-accent">Dùng thử<Arrow /></span>
              </Link>
            </Reveal>
          ))}
        </div>
        <Reveal delay={120} className="mt-6">
          <div className="flex flex-col gap-3 rounded-2xl border border-accent/20 bg-accent-soft/60 p-5 sm:flex-row sm:items-center sm:justify-between">
            <div><p className="font-semibold">Không có thời gian hoặc không rành kỹ thuật?</p><p className="mt-0.5 text-[14.5px] text-muted">Chọn các lỗi cần giúp, đội kỹ thuật VibeSec xem và gửi bạn cách xử lý kèm báo giá. Chỉ thu phí khi bạn đồng ý.</p></div>
            <Link href="/nho-chuyen-gia" className="btn-primary shrink-0">Nhờ chuyên gia<Arrow /></Link>
          </div>
        </Reveal>
      </div>
    </section>
  );
}


const FAQ: [string, string][] = [
  ["Quét có làm hại hay làm chậm website của tôi không?", "Không. Chúng tôi chỉ gửi một số ít yêu cầu đọc thông thường, giống một khách truy cập, có giới hạn tốc độ và số request. Không có payload khai thác nào được gửi."],
  ["VibeSec có phải là kiểm thử xâm nhập (pentest) không?", "Không. VibeSec là quét thụ động từ bên ngoài, giúp phát hiện sớm các lỗi cấu hình và rò rỉ phổ biến. Với hệ thống quan trọng, hãy kết hợp pentest do chuyên gia thực hiện."],
  ["Điểm cao có nghĩa là website an toàn tuyệt đối?", `Không. Điểm tối đa là ${PASSIVE_SCORE_CEILING} vì quét bên ngoài không thấy logic nghiệp vụ, phân quyền hay lỗi trong ứng dụng. Điểm là đánh giá cấu hình nhìn từ bên ngoài.`],
  ["Tôi có cần đưa mật khẩu hay quyền quản trị không?", "Không bao giờ. Quét website không cần gì ngoài địa chỉ. Quét hệ thống chỉ dùng thông tin công khai có sẵn trong website. Riêng repo riêng tư mới cần kết nối GitHub chỉ-đọc."],
  ["Tôi có thể quét website của người khác không?", "Bạn chỉ nên quét website mình sở hữu hoặc được phép kiểm tra. Hệ thống có giới hạn tần suất và chặn lạm dụng để không bị dùng sai mục đích."],
  ["Không rành kỹ thuật thì làm sao sửa?", "Mỗi lỗi có lời giải thích đời thường, các bước sửa cụ thể và đoạn lệnh chép được (kể cả prompt dán vào AI). Cần hơn nữa thì dùng tính năng Nhờ chuyên gia."],
];

export function Faq() {
  return (
    <section className="hairline" aria-labelledby="faq-h">
      <div className="container-x max-w-3xl py-14">
        <Reveal><p className="eyebrow mb-3">câu hỏi thường gặp</p><h2 id="faq-h" className="text-3xl font-semibold tracking-tight">Trả lời thẳng thắn.</h2></Reveal>
        <div className="mt-8 divide-y divide-line border-y border-line">
          {FAQ.map(([q, a]) => (
            <details key={q} className="group py-4">
              <summary className="flex cursor-pointer items-center justify-between gap-4 text-[15.5px] font-medium">{q}<svg viewBox="0 0 24 24" className="size-4 shrink-0 text-faint transition-transform duration-200 group-open:rotate-90" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9 6 6 6-6 6" /></svg></summary>
              <p className="mt-2.5 text-[15px] leading-relaxed text-muted">{a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

export function FinalCta() {
  return (
    <section className="hairline bg-surface/60" aria-label="Bắt đầu">
      <div className="container-x py-16 text-center">
        <Reveal>
          <h2 className="mx-auto max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Biết mình đang hở ở đâu trước khi người khác biết.</h2>
          <p className="mx-auto mt-4 max-w-xl text-[15.5px] leading-relaxed text-muted">Quét miễn phí trong vài chục giây. Không cần cài đặt, không cần thẻ.</p>
          <div className="mt-7 flex flex-wrap justify-center gap-3"><Link href="/signup" className="btn-primary btn-lg">Quét miễn phí<Arrow /></Link><Link href="/demo" className="btn-ghost btn-lg">Xem báo cáo demo</Link></div>
        </Reveal>
      </div>
    </section>
  );
}


const REACH_LABEL = { good: ["chip-ok", "Phủ tốt"], partial: ["chip-med", "Một phần"], none: ["chip-info", "Không thấy được"] } as const;

/**
 * MỘT khối duy nhất cho mọi thứ liên quan tới “có đáng tin không”: cam kết an toàn & riêng tư (trái) và phạm vi đối chiếu OWASP Top 10:2025 (phải, gọn một dòng/mục).
 * Số 9/10 được TÍNH từ bộ luật đang chạy, không gõ tay.
 */
export function Trust() {
  const s = stats();
  const items: [string, string][] = [
    ["Chỉ đọc, không động vào website", "Không đoán mật khẩu, không gửi mã khai thác, không ghi/sửa/xoá gì."],
    ["Mỗi kết luận có bằng chứng", "Kèm header/đoạn mã/vị trí thật, mã luật, độ tin cậy và lệnh để bạn tự kiểm tra lại."],
    ["Luật cố định, không dùng AI đoán", "Cùng mục tiêu và cùng phiên bản bộ luật cho cùng kết quả; bộ luật công khai."],
    ["Bí mật luôn được che", "Khoá, token tìm thấy chỉ hiện vài ký tự đầu; không lưu khoá bạn nhập."],
    ["Chặn quét địa chỉ nội bộ", "Nhiều lớp chống SSRF: kiểm tra URL, DNS, ghim IP; chỉ quét website công khai."],
    ["Dữ liệu của bạn, bạn quyết", "Chọn thời gian lưu 7–365 ngày, xoá bất cứ lúc nào, mã hoá khi lưu."],
  ];
  return (
    <section className="hairline bg-surface/60" aria-labelledby="trust-h">
      <div className="container-x py-14">
        <Reveal>
          <p className="eyebrow mb-3">tin được đến đâu</p>
          <h2 id="trust-h" className="max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Công cụ bảo mật thì phải đáng tin trước.</h2>
        </Reveal>
        <div className="mt-9 grid gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:gap-14">
          <ul className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
            {items.map(([t, d], i) => (
              <li key={t}><Reveal delay={(i % 2) * 80} className="flex gap-3">
                <svg viewBox="0 0 24 24" className="mt-0.5 size-5 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>
                <span><span className="block font-semibold">{t}</span><span className="mt-1 block text-[14px] leading-relaxed text-muted">{d}</span></span>
              </Reveal></li>
            ))}
          </ul>
          <Reveal delay={100}>
            <p className="text-[15px] leading-relaxed text-muted">Chạm tới <strong className="font-medium text-fg">{s.owasp}/10</strong> nhóm OWASP Top 10:2025. VibeSec là công cụ sàng lọc nhanh, <strong className="font-medium text-fg">không thay thế kiểm thử xâm nhập</strong> hay chứng nhận tuân thủ; điểm cao không có nghĩa là an toàn tuyệt đối.</p>
            <ul className="panel mt-4 divide-y divide-line overflow-hidden">
              {OWASP_TOP10.map((o) => (
                <li key={o.code} className="flex items-center gap-3 px-3.5 py-2" title={o.note}>
                  <span className="mono w-8 shrink-0 text-xs font-semibold text-faint">{o.code}</span>
                  <span className="min-w-0 flex-1 truncate text-[13.5px]">{o.name}</span>
                  <span className={`${REACH_LABEL[o.reach][0]} shrink-0`}>{REACH_LABEL[o.reach][1]}</span>
                </li>
              ))}
            </ul>
            <Link href="/phuong-phap" className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline">Đọc phương pháp chấm điểm và {ALL_RULES.length} kiểm tra<Arrow /></Link>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
