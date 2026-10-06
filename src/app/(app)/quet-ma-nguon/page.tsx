import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { CodeScanForm } from "@/components/CodeScanForm";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ProjectScanList } from "@/components/ProjectScanList";
import { ScanCovers, type CoverGroup } from "@/components/ScanCovers";
import { cookies } from "next/headers";
import { env } from "@/lib/env";
import { TOKEN_COOKIE } from "@/lib/github/oauth";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { listProjectScans } from "@/lib/db/project-repo";

export const metadata: Metadata = { title: "Quét mã nguồn" };
export const dynamic = "force-dynamic";

const GROUPS: CoverGroup[] = [
  { title: "Khoá bí mật & mật khẩu", simple: "Tìm khoá API, token, mật khẩu lỡ viết thẳng vào code. Giá trị luôn được ẩn.", tech: ["Mẫu khoá theo nhà cung cấp (AWS, Stripe, GitHub, OpenAI, Supabase service_role…)", "Mật khẩu viết cứng theo tên biến + độ ngẫu nhiên", "Chuỗi kết nối database có mật khẩu"] },
  { title: "File nhạy cảm", simple: "Tìm file .env, khoá riêng tư hay file database lỡ đưa lên kho.", tech: [".env* có giá trị thật", "*.pem / *.key / id_rsa", "service account, .npmrc token, tfstate, *.sqlite, dump"] },
  { title: "Thư viện có lỗi", simple: "Đối chiếu thư viện bạn dùng với danh sách lỗ hổng đã công bố, và báo thư viện quá cũ.", tech: ["OSV.dev (CVE/GHSA) từ package-lock, yarn.lock, requirements.txt", "So với phiên bản mới nhất trên npm registry", "Thiếu lockfile"] },
  { title: "Cách viết code kém an toàn", simple: "Phát hiện những kiểu code hay dẫn tới bị tấn công và chỉ cách sửa.", tech: ["eval / innerHTML / SQL ghép chuỗi / exec ghép chuỗi", "TLS tắt, CORS *, JWT lỏng, MD5 cho mật khẩu", "NEXT_PUBLIC_*SECRET, service_role trong 'use client'"] },
];

export default async function Page({ searchParams }: { searchParams: Promise<{ repo?: string; github?: string }> }) {
  const { repo, github } = await searchParams;
  const user = await getUser();
  if (!user) redirect("/login?next=/quet-ma-nguon");
  const scans = await listProjectScans(await getDb(), user.id, "code", 3);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">quét mã nguồn</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Quét mã nguồn</h1>
      <MatMatSays className="mt-5 max-w-2xl" text="Dán kho GitHub của bạn, mình đọc thử xem có khoá bí mật hay chỗ hở nào lỡ nằm trong code không." />
      <div className="mt-6 max-w-3xl"><CodeScanForm initialRepo={repo ?? ""} githubEnabled={env.githubEnabled} connected={!!(await cookies()).get(TOKEN_COOKIE)} />
        {github === "failed" && <p role="alert" className="mt-3 text-sm text-crit">Kết nối GitHub không thành công. Vui lòng thử lại.</p>}</div>
      <p className="mt-3 text-[13px] text-faint">Chỉ đọc · Không chạy code của bạn · Không lưu token · Bí mật luôn được ẩn</p>
      <section className="mt-8" aria-label="Gồm những gì"><h2 className="eyebrow">gồm những gì</h2><ScanCovers groups={GROUPS} columns /></section>
      <section className="mt-10" aria-label="Gần đây"><h2 className="text-lg font-semibold tracking-tight">Gần đây</h2><ProjectScanList scans={scans} base="/quet-ma-nguon" empty="Chưa có lượt quét mã nguồn nào." /></section>
    </div>
  );
}
