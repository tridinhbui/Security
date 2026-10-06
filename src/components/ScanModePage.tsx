import { redirect } from "next/navigation";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ScanForm } from "@/components/ScanForm";
import { ScanCovers, type CoverGroup } from "@/components/ScanCovers";
import { ScanTable } from "@/components/ScanTable";
import Link from "next/link";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

/** Nhóm "gồm những gì" của quét nâng cao: tên + một câu đời thường (Dễ hiểu) và danh sách kiểm tra chi tiết (Kỹ thuật). */
const ADVANCED_GROUPS: CoverGroup[] = [
  { title: "Mã JavaScript", simple: "Đọc mã của trang để tìm khoá bí mật hay thư viện cũ lỡ để lộ.",
    tech: ["Phân tích mã: DOM XSS, postMessage, token trong localStorage, GraphQL", "Chuỗi cung ứng script: nguồn từng bị chiếm dụng, không ghim phiên bản", "Khoá bí mật và thư viện lỗi thời (CVE)"] },
  { title: "API & endpoint", simple: "Tìm các đường dẫn quản trị hoặc API vô tình bị lộ trong mã trang.",
    tech: ["Bản đồ endpoint API/quản trị lộ trong mã trang", "Chuỗi chuyển hướng, header nhất quán giữa các trang"] },
  { title: "Cookie & phiên đăng nhập", simple: "Kiểm tra phiên đăng nhập có bị lưu nhầm hoặc dùng quá lâu không.",
    tech: ["Rò rỉ phiên qua cache dùng chung", "Phạm vi và tuổi thọ cookie", "Cờ Secure / HttpOnly / SameSite, tiền tố __Host-"] },
  { title: "CSP & cấu hình bảo mật", simple: "Xem các lớp bảo vệ của trang có đủ chặt và cấu hình đúng không.",
    tech: ["CSP: unsafe-inline, nguồn quá rộng, thiếu object-src / base-uri", "Vệ sinh chứng chỉ TLS", "SPF / DMARC chi tiết: +all, vượt 10 lần tra, p=none"] },
];

const COPY = {
  basic: {
    path: "/quet-co-ban", eyebrow: "quét cơ bản", title: "Quét cơ bản", mode: "quick" as const,
    say: "Dán URL → kiểm tra nhanh các cấu hình bảo mật phổ biến trong ~10 giây.",
    covers: ["Ổ khoá HTTPS có hoạt động không", "Các thiết lập bảo vệ trang web", "Cookie và email giả mạo", "Kết quả kèm cách sửa dễ hiểu"],
    when: "",
  },
  advanced: {
    path: "/quet-nang-cao", eyebrow: "quét nâng cao", title: "Quét nâng cao", mode: "full" as const,
    say: "Quét sâu mã nguồn và cấu hình để phát hiện các rủi ro khó thấy hơn.",
    covers: [],
    when: "",
  },
};

/** Trang quét dùng chung cho hai kiểu: cơ bản (quét nhanh) và nâng cao (quét đầy đủ). Hiển thị lịch sử của đúng kiểu đó. */
export async function ScanModePage({ kind, prefill }: { kind: "basic" | "advanced"; prefill?: string }) {
  const c = COPY[kind];
  const user = await getUser();
  if (!user) redirect(`/login?next=${c.path}`);
  const all = await repo.listScans(await getDb(), user.id, 100);
  const scans = all.filter((s) => s.mode === c.mode).slice(0, 3);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">{c.eyebrow}</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">{c.title}</h1>
      {kind === "basic" ? <p className="mt-3 max-w-2xl text-[16px] leading-relaxed text-muted">{c.say}</p> : <MatMatSays className="mt-5 max-w-2xl" text={c.say} />}
      <div className="mt-6 max-w-3xl"><ScanForm authed mode={kind} initialUrl={prefill ?? ""} label={kind === "basic" ? "Quét cơ bản" : "Quét nâng cao"} /></div>
      <p className="mt-3 text-[13px] text-faint">Quét thụ động · Không đăng nhập · Không thay đổi website</p>
      <section className="mt-8" aria-label="Kiểu quét này làm gì">
        <h2 className="eyebrow">gồm những gì</h2>
        {kind === "advanced"
          ? <ScanCovers groups={ADVANCED_GROUPS} columns />
          : <ul className="mt-3 grid gap-2 text-[15px] text-muted sm:grid-cols-2">{c.covers.map((t) => <li key={t} className="flex gap-2.5"><span className="mt-1 text-ok" aria-hidden>✓</span>{t}</li>)}</ul>}
      </section>
      {scans.length > 0 && <section className="mt-10" aria-label="Lượt quét gần đây">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="text-lg font-semibold tracking-tight">Gần đây</h2>
          <Link href="/scans" className="text-sm font-medium text-accent hover:underline">Xem tất cả →</Link>
        </div>
        <ScanTable scans={scans} />
      </section>}
    </div>
  );
}
