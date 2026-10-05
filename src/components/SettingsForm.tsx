"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ConfirmDialog } from "./ConfirmDialog";

export function SettingsForm({ retention }: { retention: number }) {
  const router = useRouter();
  const [value, setValue] = useState(retention);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [busy, setBusy] = useState(false);

  async function save(v: number) {
    setValue(v); setMsg(null);
    const res = await fetch("/api/settings", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ retention_days: v }) });
    setMsg(res.ok ? { ok: true, text: "Đã lưu. Các báo cáo hiện có sẽ áp dụng thời gian lưu trữ mới." } : { ok: false, text: "Không thể lưu cài đặt này." });
  }
  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }
  async function wipe() {
    setBusy(true);
    const res = await fetch("/api/scans", { method: "DELETE" });
    setBusy(false); setConfirmWipe(false);
    if (res.ok) { setMsg({ ok: true, text: "Đã xoá tất cả báo cáo." }); router.refresh(); } else setMsg({ ok: false, text: "Không thể xoá báo cáo." });
  }
  return (
    <div className="space-y-10">
      <section aria-labelledby="ret-h">
        <h2 id="ret-h" className="text-base font-semibold">Thời gian lưu trữ dữ liệu</h2>
        <p className="mt-1 max-w-xl text-sm text-muted">Báo cáo sẽ tự động bị xoá sau khoảng thời gian này kể từ khi hoàn tất. Thời gian càng ngắn thì càng riêng tư.</p>
        <div role="radiogroup" aria-label="Thời gian lưu trữ" className="mt-4 inline-flex rounded-lg border border-line-strong bg-surface p-0.5">
          {[7, 30, 90, 365].map((d) => (
            <button key={d} role="radio" aria-checked={value === d} onClick={() => save(d)} className={`h-9 rounded-md px-4 text-sm font-medium transition-colors ${value === d ? "bg-white text-fg shadow-crisp" : "text-muted hover:text-fg"}`}>{d === 365 ? "1 năm" : `${d} ngày`}</button>
          ))}
        </div>
      </section>

      <section aria-labelledby="ses-h" className="hairline pt-8">
        <h2 id="ses-h" className="text-base font-semibold">Phiên đăng nhập</h2>
        <p className="mt-1 text-sm text-muted">Đăng xuất khỏi thiết bị này.</p>
        <button onClick={signOut} className="btn-ghost mt-4">Đăng xuất</button>
      </section>

      <section aria-labelledby="dng-h" className="rounded-xl border border-crit/25 bg-crit/[0.03] p-5">
        <h2 id="dng-h" className="text-base font-semibold text-crit">Vùng nguy hiểm</h2>
        <p className="mt-1 max-w-xl text-sm text-muted">Xoá mọi báo cáo, phát hiện và liên kết chia sẻ thuộc tài khoản của bạn. Không thể hoàn tác.</p>
        <button onClick={() => setConfirmWipe(true)} className="btn-danger mt-4">Xoá tất cả báo cáo của tôi</button>
      </section>

      {msg && <p role="status" className={`pop text-sm ${msg.ok ? "text-ok" : "text-crit"}`}>{msg.text}</p>}
      <ConfirmDialog open={confirmWipe} danger busy={busy} title="Xoá TẤT CẢ báo cáo?" description="Toàn bộ báo cáo, phát hiện và liên kết chia sẻ của bạn sẽ bị xoá vĩnh viễn. Không thể hoàn tác thao tác này." confirmLabel="Xoá tất cả" onConfirm={wipe} onCancel={() => setConfirmWipe(false)} />
    </div>
  );
}
