import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ProjectScanList } from "@/components/ProjectScanList";
import { ScanCovers, type CoverGroup } from "@/components/ScanCovers";
import { SystemScanForm } from "@/components/SystemScanForm";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { listProjectScans } from "@/lib/db/project-repo";

export const metadata: Metadata = { title: "Quét hệ thống" };
export const dynamic = "force-dynamic";

const GROUPS: CoverGroup[] = [
  { title: "Dữ liệu có bị mở không", simple: "Thử xem người lạ có đọc được bảng dữ liệu của bạn không (chỉ đếm, không tải).", tech: ["Supabase: RLS qua PostgREST HEAD + Content-Range", "Firebase: Realtime DB rules, Firestore listCollectionIds", "Cấu trúc schema / RPC / GraphQL introspection"] },
  { title: "File lưu trữ", simple: "Kiểm tra kho ảnh, tài liệu có bị công khai hoặc liệt kê được không.", tech: ["Supabase Storage: bucket public, listing", "Firebase Storage: list objects ẩn danh"] },
  { title: "Đăng nhập", simple: "Xem ai cũng đăng ký được không, có cần xác nhận email không.", tech: ["Supabase Auth settings (autoconfirm, signup)", "Firebase authorizedDomains, anonymous, API key restriction"] },
  { title: "API & CORS", simple: "Xem API có cho website lạ gọi vào một cách nguy hiểm không.", tech: ["CORS reflect origin + credentials", "Endpoint lộ công khai"] },
];

export default async function Page({ searchParams }: { searchParams: Promise<{ stack?: string; ref?: string; site?: string }> }) {
  const sp = await searchParams;
  const user = await getUser();
  if (!user) redirect("/login?next=/quet-he-thong");
  const scans = await listProjectScans(await getDb(), user.id, "system", 3);
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">quét hệ thống</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Quét hệ thống</h1>
      <MatMatSays className="mt-5 max-w-2xl" text="Chọn nơi dự án của bạn chạy. Mình chỉ hỏi như một người lạ ‘cho tôi xem dữ liệu được không?’, không ghi hay sửa gì hết." />
      <div className="mt-6"><SystemScanForm initialStack={sp.stack === "firebase" ? "firebase" : "supabase"} initialRef={sp.ref ?? ""} initialSite={sp.site ?? ""} /></div>
      <section className="mt-10" aria-label="Gồm những gì"><h2 className="eyebrow">gồm những gì</h2><ScanCovers groups={GROUPS} columns /></section>
      <section className="mt-10" aria-label="Gần đây"><h2 className="text-lg font-semibold tracking-tight">Gần đây</h2><ProjectScanList scans={scans} base="/quet-he-thong" empty="Chưa có lượt quét hệ thống nào." /></section>
    </div>
  );
}
