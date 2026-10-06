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

/** Dải chuẩn tham chiếu ngay dưới hero. Chữ thuần, không logo: chúng tôi tham chiếu chuẩn mở, không phải được các tổ chức này chứng nhận. */
export function StandardsStrip() {
  const items = ["OWASP Top 10 (2021)", "CWE · MITRE", "OWASP ASVS 4.0.3", "OWASP WSTG", "OSV.dev", "npm registry"];
  return (
    <section className="hairline bg-surface/60" aria-labelledby="std-h">
      <div className="container-x py-7">
        <p id="std-h" className="eyebrow text-center">đối chiếu theo chuẩn và nguồn dữ liệu mở</p>
        <ul className="mt-4 flex flex-wrap items-center justify-center gap-x-3 gap-y-2">
          {items.map((t) => <li key={t} className="mono rounded-md border border-line-strong bg-white px-3 py-1.5 text-[12.5px] font-medium text-fg/80 shadow-crisp">{t}</li>)}
        </ul>
        <p className="mt-3 text-center text-[12.5px] text-faint">Đây là chuẩn và cơ sở dữ liệu công khai mà kết quả được đối chiếu tới; không phải chứng nhận hay bảo chứng từ các tổ chức này.</p>
      </div>
    </section>
  );
}

export function NumbersBand() {
  const s = stats();
  const cells: [number, string, string][] = [
    [s.rules, "kiểm tra bảo mật", "Mỗi kiểm tra là một luật cố định, có thể tái lập."],
    [s.cwe, "mã lỗi CWE", "Ánh xạ tới danh mục điểm yếu phần mềm của MITRE."],
    [s.asvs, "yêu cầu OWASP ASVS", "Đối chiếu tới tiêu chuẩn xác minh bảo mật ứng dụng."],
    [0, "payload khai thác", "Chỉ đọc thông tin công khai. Không tấn công thử."],
  ];
  return (
    <section className="hairline" aria-label="Con số">
      <div className="container-x py-12">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-8 lg:grid-cols-4">
          {cells.map(([n, label, hint], i) => (
            <Reveal key={label} delay={i * 80}>
              <dt className="text-sm font-medium text-muted">{label}</dt>
              <dd className="num mt-1 text-5xl font-semibold tracking-tight"><AnimatedNumber value={n} delay={200 + i * 120} /></dd>
              <dd className="mt-2 text-[13.5px] leading-relaxed text-muted">{hint}</dd>
            </Reveal>
          ))}
        </dl>
      </div>
    </section>
  );
}

/** Nguồn gốc: người dùng truy ngược được từng kết luận về bằng chứng, luật và nguồn dữ liệu. */
export function Provenance() {
  const cards = [
    { d: "M4 6h16M4 12h16M4 18h10", t: "Mỗi kết luận có bằng chứng", p: "Mọi phát hiện kèm bằng chứng cụ thể (header, đoạn mã, vị trí file), mã luật và độ tin cậy. Bạn tự kiểm tra lại được, kể cả bằng lệnh chỉ đọc chúng tôi cung cấp." },
    { d: "M12 3 4.5 6v5.5c0 4.4 3 7.9 7.5 9.5 4.5-1.6 7.5-5.1 7.5-9.5V6L12 3Zm-2.5 9 2 2 3.5-4", t: "Luật cố định, không đoán mò", p: "Không dùng AI để “đoán” lỗ hổng. Cùng một mục tiêu và cùng phiên bản bộ luật sẽ ra cùng kết quả, và bộ luật được công bố đầy đủ." },
    { d: "M3 12a9 9 0 1 0 3-6.7M3 4v5h5", t: "Dữ liệu lỗ hổng từ nguồn mở", p: "Thư viện có lỗ hổng được đối chiếu với OSV.dev (CVE, GHSA) và bản mới nhất trên npm registry. Mỗi lỗ hổng ghi rõ mã tham chiếu và bản vá." },
    { d: "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3V4Zm0 13a3 3 0 0 1 3-3h10", t: "Cách chấm điểm công khai", p: `Điểm = 100 trừ theo mức độ và độ tin cậy, có trần điểm. Không website nào đạt 100: tối đa ${PASSIVE_SCORE_CEILING}, vì quét từ bên ngoài không thể chứng minh an toàn tuyệt đối.` },
  ];
  return (
    <section className="hairline" aria-labelledby="prov-h">
      <div className="container-x py-14">
        <Reveal><p className="eyebrow mb-3">nguồn gốc kết quả</p><h2 id="prov-h" className="max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Biết rõ kết quả đến từ đâu, và tin được đến đâu.</h2></Reveal>
        <div className="mt-9 grid gap-4 sm:grid-cols-2">
          {cards.map((c, i) => (
            <Reveal key={c.t} delay={(i % 2) * 90}>
              <div className="panel h-full p-6 transition-shadow hover:shadow-pop"><Ico d={c.d} /><h3 className="mt-4 text-[16px] font-semibold">{c.t}</h3><p className="mt-2 text-[14.5px] leading-relaxed text-muted">{c.p}</p></div>
            </Reveal>
          ))}
        </div>
        <Reveal className="mt-6"><Link href="/phuong-phap" className="text-sm font-medium text-accent hover:underline">Đọc phương pháp chấm điểm và danh sách {ALL_RULES.length} kiểm tra →</Link></Reveal>
      </div>
    </section>
  );
}

const REACH = { good: ["chip-ok", "Phủ tốt"], partial: ["chip-med", "Phủ một phần"], none: ["chip-info", "Không kiểm tra được"] } as const;

/** Minh bạch phạm vi: nói thẳng chỗ nào phủ tốt, chỗ nào không (OWASP Top 10) — chính là lý do để người dùng tin phần còn lại. */
export function CoverageTable() {
  const s = stats();
  return (
    <section className="hairline bg-surface/60" aria-labelledby="cov-h">
      <div className="container-x grid gap-10 py-14 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
        <Reveal from="left">
          <p className="eyebrow mb-3">minh bạch phạm vi</p>
          <h2 id="cov-h" className="text-3xl font-semibold tracking-tight">Chúng tôi nói rõ cái gì quét được và không.</h2>
          <p className="mt-4 text-[15px] leading-relaxed text-muted">Quét từ bên ngoài chạm tới <strong className="font-medium text-fg">{s.owasp}/10</strong> nhóm trong OWASP Top 10. Hai nhóm còn lại cần truy cập bên trong hệ thống hoặc gửi payload tấn công, nên chúng tôi cố ý bỏ qua thay vì làm ra vẻ bao phủ.</p>
          <p className="mt-3 text-[15px] leading-relaxed text-muted">VibeSec là công cụ sàng lọc nhanh và chỉ đường sửa, <strong className="font-medium text-fg">không thay thế kiểm thử xâm nhập (pentest)</strong> hay chứng nhận tuân thủ.</p>
        </Reveal>
        <Reveal from="right" delay={100}>
          <ul className="panel divide-y divide-line overflow-hidden">
            {OWASP_TOP10.map((o) => (
              <li key={o.code} className="flex items-start gap-3 px-4 py-3">
                <span className="mono mt-0.5 w-9 shrink-0 text-xs font-semibold text-faint">{o.code}</span>
                <span className="min-w-0 flex-1"><span className="block text-[14.5px] font-medium leading-snug">{o.name}</span><span className="mt-0.5 block text-[13px] leading-relaxed text-muted">{o.note}</span></span>
                <span className={`${REACH[o.reach][0]} hidden shrink-0 sm:inline-flex`}>{REACH[o.reach][1]}</span>
              </li>
            ))}
          </ul>
        </Reveal>
      </div>
    </section>
  );
}

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

/** Cam kết an toàn & riêng tư: chỉ liệt kê điều hệ thống thật sự làm (đối chiếu với mã nguồn). */
export function Commitments() {
  const items: [string, string][] = [
    ["Quét thụ động, chỉ đọc", "Không đoán mật khẩu, không gửi payload khai thác, không ghi/sửa/xoá dữ liệu của bạn."],
    ["Bí mật luôn được che", "Khoá, token, mật khẩu tìm thấy chỉ hiện ký tự đầu và độ dài, không bao giờ hiện đầy đủ."],
    ["Không lưu khoá bạn nhập", "Token GitHub hay khoá công khai chỉ dùng trong lượt quét; kết nối GitHub tự hết hạn sau 1 giờ."],
    ["Chặn quét địa chỉ nội bộ", "Nhiều lớp bảo vệ SSRF: kiểm tra URL, DNS, ghim IP. Chỉ quét website công khai."],
    ["Dữ liệu của bạn, bạn quyết", "Chọn thời gian lưu 7 đến 365 ngày, xoá báo cáo bất cứ lúc nào, chỉ chủ báo cáo mới xem được."],
    ["Header gốc được mã hoá khi lưu", "Dữ liệu nhạy cảm của lượt quét được mã hoá AES-256-GCM; giá trị cookie bị loại bỏ."],
  ];
  return (
    <section className="hairline bg-surface/60" aria-labelledby="com-h">
      <div className="container-x py-14">
        <Reveal><p className="eyebrow mb-3">cam kết an toàn & riêng tư</p><h2 id="com-h" className="max-w-2xl text-3xl font-semibold tracking-tight sm:text-4xl">Công cụ bảo mật thì phải đáng tin trước.</h2></Reveal>
        <ul className="mt-9 grid gap-x-10 gap-y-6 sm:grid-cols-2 lg:grid-cols-3">
          {items.map(([t, d], i) => (
            <li key={t}><Reveal delay={(i % 3) * 80} className="flex gap-3">
              <svg viewBox="0 0 24 24" className="mt-0.5 size-5 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>
              <span><span className="block font-semibold">{t}</span><span className="mt-1 block text-[14.5px] leading-relaxed text-muted">{d}</span></span>
            </Reveal></li>
          ))}
        </ul>
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
