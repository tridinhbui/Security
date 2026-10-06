import { redirect } from "next/navigation";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ScanForm } from "@/components/ScanForm";
import { ScanTable } from "@/components/ScanTable";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";

const COPY = {
  basic: {
    path: "/quet-co-ban", eyebrow: "quét cơ bản", title: "Quét cơ bản", mode: "quick" as const,
    say: "Quét cơ bản giống như đi một vòng quanh nhà xem cửa chính đã khoá chưa. Nhanh, nhẹ, chỉ mất khoảng 10 giây 🚪",
    covers: ["Ổ khoá HTTPS và chứng chỉ", "Các “biển báo an toàn” (HTTP header)", "Cookie, DNS và cấu hình email", "Bỏ qua việc tải và đọc file JavaScript"],
    when: "Phù hợp khi bạn muốn kiểm tra nhanh, hoặc quét lại sau khi sửa một cấu hình nhỏ.",
  },
  advanced: {
    path: "/quet-nang-cao", eyebrow: "quét nâng cao", title: "Quét nâng cao", mode: "full" as const,
    say: "Quét nâng cao mình đọc kỹ cả mã của trang để tìm thứ lỡ để lộ, như khoá bí mật hay thư viện cũ. Lâu hơn một chút nhưng sâu hơn nhiều 🔍",
    covers: ["Tất cả kiểm tra của quét cơ bản", "Phân tích sâu CSP: unsafe-inline, nguồn quá rộng, thiếu object-src/base-uri", "Rò rỉ phiên qua cache dùng chung, phạm vi và tuổi thọ cookie", "Chuỗi cung ứng script: nguồn từng bị chiếm dụng, không ghim phiên bản", "Phân tích mã JavaScript: DOM XSS, postMessage, token trong localStorage, GraphQL", "Bản đồ endpoint API/quản trị lộ trong mã trang", "Chuỗi chuyển hướng, header nhất quán giữa các trang, vệ sinh chứng chỉ", "SPF/DMARC chi tiết: +all, vượt 10 lần tra, p=none"],
    when: "Phù hợp khi bạn sắp ra mắt website, hoặc muốn kiểm tra thật kỹ.",
  },
};

/** Trang quét dùng chung cho hai kiểu: cơ bản (quét nhanh) và nâng cao (quét đầy đủ). Hiển thị lịch sử của đúng kiểu đó. */
export async function ScanModePage({ kind, prefill }: { kind: "basic" | "advanced"; prefill?: string }) {
  const c = COPY[kind];
  const user = await getUser();
  if (!user) redirect(`/login?next=${c.path}`);
  const all = await repo.listScans(await getDb(), user.id, 100);
  const scans = all.filter((s) => s.mode === c.mode).slice(0, 8);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">{c.eyebrow}</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">{c.title}</h1>
      <MatMatSays className="mt-5 max-w-2xl" text={c.say} />
      <div className="mt-6 max-w-3xl"><ScanForm authed mode={kind} initialUrl={prefill ?? ""} label={kind === "basic" ? "Quét cơ bản" : "Quét nâng cao"} /></div>
      <section className="panel mt-8 p-5" aria-label="Kiểu quét này làm gì">
        <h2 className="eyebrow">gồm những gì</h2>
        <ul className="mt-3 grid gap-2 text-[15px] text-muted">{c.covers.map((t) => <li key={t} className="flex gap-2.5"><span className="mt-1 text-ok" aria-hidden>✓</span>{t}</li>)}</ul>
        <p className="mt-4 text-sm text-muted">{c.when}</p>
      </section>
      <section className="mt-10" aria-label="Lượt quét gần đây">
        <h2 className="text-xl font-semibold tracking-tight">Lượt {kind === "basic" ? "quét cơ bản" : "quét nâng cao"} gần đây</h2>
        <ScanTable scans={scans} />
      </section>
    </div>
  );
}
