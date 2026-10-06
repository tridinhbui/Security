import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { LaunchForm } from "@/components/LaunchForm";
import { MatMatSays } from "@/components/matmat/MatMatSays";
import { ProjectScanList } from "@/components/ProjectScanList";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import { listProjectScans } from "@/lib/db/project-repo";
import * as repo from "@/lib/db/repo";

export const metadata: Metadata = { title: "Quét trước ra mắt" };
export const dynamic = "force-dynamic";

export default async function Page() {
  const user = await getUser();
  if (!user) redirect("/login?next=/truoc-ra-mat");
  const db = await getDb();
  const [scans, codes, systems, launches] = await Promise.all([repo.listScans(db, user.id, 40), listProjectScans(db, user.id, "code", 20), listProjectScans(db, user.id, "system", 20), listProjectScans(db, user.id, "launch", 5)]);
  const websites = scans.filter((s) => s.status === "completed").map((s) => ({ id: s.id, label: s.host, at: s.completed_at ?? s.created_at, note: s.mode === "quick" ? "cơ bản" : "nâng cao" }));
  return (
    <div className="container-x max-w-4xl py-10 sm:py-14">
      <p className="eyebrow reveal">quét trước ra mắt</p>
      <h1 className="reveal mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Quét trước ra mắt</h1>
      <MatMatSays className="mt-5 max-w-2xl" text="Mình gom kết quả website, mã nguồn và hệ thống của bạn lại, rồi nói thẳng: nên ra mắt chưa, và còn gì bắt buộc phải sửa." />
      <div className="mt-6"><LaunchForm websites={websites} codes={codes.map((c) => ({ id: c.id, label: c.label, at: c.created_at }))} systems={systems.map((c) => ({ id: c.id, label: c.label, at: c.created_at }))} /></div>
      <section className="mt-10" aria-label="Gần đây"><h2 className="text-lg font-semibold tracking-tight">Các lần đánh giá</h2><ProjectScanList scans={launches} base="/truoc-ra-mat" empty="Chưa có lần đánh giá nào." /></section>
    </div>
  );
}
