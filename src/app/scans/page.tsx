import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getUser } from "@/lib/auth/next";
import { getDb } from "@/lib/cf";
import * as repo from "@/lib/db/repo";
import { ScanTable } from "@/components/ScanTable";

export const metadata: Metadata = { title: "Scan history" };
export const dynamic = "force-dynamic";

export default async function History() {
  const user = await getUser();
  if (!user) redirect("/login?next=/scans");
  const scans = await repo.listScans(await getDb(), user.id, 200);
  return (
    <div className="mx-auto max-w-5xl px-5 py-10">
      <div className="flex items-baseline justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Scan history</h1>
        <Link href="/dashboard" className="text-sm text-muted hover:text-fg">← Dashboard</Link>
      </div>
      <p className="text-sm text-muted mt-1.5">Reports are kept according to your <Link className="underline underline-offset-2" href="/settings">retention setting</Link>.</p>
      <ScanTable scans={scans} />
    </div>
  );
}
