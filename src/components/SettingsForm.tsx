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
    setMsg(res.ok ? "Đã lưu. Các báo cáo hiện có sẽ áp dụng thời gian lưu trữ mới." : "Không thể lưu cài đặt này.");
  }
  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }
  async function wipe() {
    if (!confirm("Xoá vĩnh viễn TẤT CẢ báo cáo của bạn? Không thể hoàn tác thao tác này.")) return;
    const res = await fetch("/api/scans", { method: "DELETE" });
    if (res.ok) { setMsg("Đã xoá tất cả báo cáo."); router.refresh(); } else setMsg("Không thể xoá báo cáo.");
  }
  return (
    <div className="space-y-10">
      <section>
        <h2 className="font-medium">Thời gian lưu trữ dữ liệu</h2>
        <p className="text-sm text-muted mt-1">Báo cáo sẽ tự động bị xoá sau khoảng thời gian này kể từ khi hoàn tất. Thời gian càng ngắn thì càng riêng tư.</p>
        <div role="radiogroup" aria-label="Thời gian lưu trữ" className="mt-4 flex flex-wrap gap-2">
          {[7, 30, 90, 365].map((d) => (
            <button key={d} role="radio" aria-checked={value === d} onClick={() => save(d)} className={`h-9 px-4 rounded-md border text-sm ${value === d ? "border-fg bg-raised" : "border-line-strong text-muted hover:text-fg"}`}>{d === 365 ? "1 năm" : `${d} ngày`}</button>
          ))}
        </div>
      </section>
      <section>
        <h2 className="font-medium">Xoá tất cả báo cáo</h2>
        <p className="text-sm text-muted mt-1">Xoá mọi báo cáo, phát hiện và liên kết chia sẻ thuộc tài khoản của bạn.</p>
        <button onClick={wipe} className="mt-4 h-9 px-4 rounded-md border border-line-strong text-sm text-high hover:border-high/60">Xoá tất cả báo cáo của tôi</button>
      </section>
      <section>
        <h2 className="font-medium">Phiên đăng nhập</h2>
        <button onClick={signOut} className="mt-4 h-9 px-4 rounded-md border border-line-strong text-sm hover:border-fg/50">Đăng xuất</button>
      </section>
      {msg && <p role="status" className="text-sm text-muted">{msg}</p>}
    </div>
  );
}
