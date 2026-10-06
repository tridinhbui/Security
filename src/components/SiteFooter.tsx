import Link from "next/link";

export function SiteFooter() {
  return (
    <footer className="mt-0 border-t border-line bg-white">
      <div className="container-x flex flex-col gap-6 py-10 text-sm text-muted md:flex-row md:items-start md:justify-between">
        <div className="max-w-md">
          <p className="mono flex items-center gap-2 text-[13px] font-medium text-fg"><span className="inline-block size-2 rounded-[3px] bg-accent" aria-hidden /><span className="uppercase tracking-[0.28em]">vibesec</span></p>
          <p className="mt-3 leading-relaxed">Chỉ thực hiện các kiểm tra thụ động, không phá hoại. Điểm số là đánh giá cấu hình từ bên ngoài, không phải bằng chứng website an toàn tuyệt đối.</p>
        </div>
        <nav aria-label="Liên kết chân trang" className="flex flex-wrap gap-x-6 gap-y-2">
          <Link className="hover:text-fg" href="/demo">Bản demo</Link>
          <Link className="hover:text-fg" href="/#checks">Những gì chúng tôi kiểm tra</Link>
          <Link className="hover:text-fg" href="/phuong-phap">Phương pháp</Link>
        </nav>
      </div>
    </footer>
  );
}
