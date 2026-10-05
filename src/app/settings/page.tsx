import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Avatar } from "@/components/UserMenu";
import { SettingsForm } from "@/components/SettingsForm";
import { getUser } from "@/lib/auth/next";

export const metadata: Metadata = { title: "Cài đặt" };
export const dynamic = "force-dynamic";

export default async function Settings() {
  const user = await getUser();
  if (!user) redirect("/login?next=/settings");
  return (
    <div className="container-x max-w-2xl py-10 sm:py-14">
      <h1 className="reveal text-3xl font-semibold tracking-tight">Cài đặt</h1>
      <div className="reveal panel mb-10 mt-6 flex items-center gap-4 p-4" style={{ ["--i" as string]: 1 }}>
        <Avatar name={user.name} email={user.email} url={user.avatar_url} size={48} />
        <div className="min-w-0">
          {user.name && <p className="truncate font-medium">{user.name}</p>}
          <p className="truncate text-sm text-muted">{user.email}</p>
        </div>
      </div>
      <SettingsForm retention={user.retention_days} />
    </div>
  );
}
