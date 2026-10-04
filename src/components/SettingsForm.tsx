"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function SettingsForm({ retention }: { retention: number }) {
  const router = useRouter();
  const [value, setValue] = useState(retention);
  const [msg, setMsg] = useState<string | null>(null);

  async function save(v: number) {
    setValue(v); setMsg(null);
    const res = await fetch("/api/settings", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ retention_days: v }) });
    setMsg(res.ok ? "Saved. Existing reports now follow the new period." : "Couldn't save that setting.");
  }
  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }
  async function wipe() {
    if (!confirm("Delete ALL of your reports permanently? This can't be undone.")) return;
    const res = await fetch("/api/scans", { method: "DELETE" });
    if (res.ok) { setMsg("All reports deleted."); router.refresh(); } else setMsg("Couldn't delete reports.");
  }
  return (
    <div className="space-y-10">
      <section>
        <h2 className="font-medium">Data retention</h2>
        <p className="text-sm text-muted mt-1">Reports are deleted automatically this long after they complete. Shorter is more private.</p>
        <div role="radiogroup" aria-label="Retention period" className="mt-4 flex flex-wrap gap-2">
          {[7, 30, 90, 365].map((d) => (
            <button key={d} role="radio" aria-checked={value === d} onClick={() => save(d)} className={`h-9 px-4 rounded-md border text-sm ${value === d ? "border-fg bg-raised" : "border-line-strong text-muted hover:text-fg"}`}>{d === 365 ? "1 year" : `${d} days`}</button>
          ))}
        </div>
      </section>
      <section>
        <h2 className="font-medium">Delete all reports</h2>
        <p className="text-sm text-muted mt-1">Removes every report, finding and share link for your account.</p>
        <button onClick={wipe} className="mt-4 h-9 px-4 rounded-md border border-line-strong text-sm text-high hover:border-high/60">Delete all my reports</button>
      </section>
      <section>
        <h2 className="font-medium">Session</h2>
        <button onClick={signOut} className="mt-4 h-9 px-4 rounded-md border border-line-strong text-sm hover:border-fg/50">Sign out</button>
      </section>
      {msg && <p role="status" className="text-sm text-muted">{msg}</p>}
    </div>
  );
}
