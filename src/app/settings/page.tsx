import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { SettingsForm } from "@/components/SettingsForm";
import { getUser } from "@/lib/auth/next";

export const metadata: Metadata = { title: "Cài đặt" };
export const dynamic = "force-dynamic";

export default async function Settings() {
  const user = await getUser();
  if (!user) redirect("/login?next=/settings");
  return (
    <div className="mx-auto max-w-xl px-5 py-10">
      <h1 className="text-2xl font-semibold tracking-tight">Cài đặt</h1>
      <p className="text-sm text-muted mt-1 mb-10">{user.email}</p>
      <SettingsForm retention={user.retention_days} />
    </div>
  );
}
