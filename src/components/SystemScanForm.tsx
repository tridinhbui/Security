"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type Stack = "supabase" | "firebase";
const STACKS: { id: Stack; name: string; hint: string }[] = [
  { id: "supabase", name: "Supabase", hint: "Database, Storage, Auth" },
  { id: "firebase", name: "Firebase", hint: "Firestore, Realtime DB, Storage" },
];
function Field({ label, hint, id, ...p }: { label: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-[13px] font-medium">{label}</label>
      <input id={id} autoComplete="off" autoCapitalize="none" spellCheck={false} className="input" {...p} />
      {hint && <p className="mt-1 text-[12.5px] text-muted">{hint}</p>}
    </div>
  );
}
const split = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

/** Chọn stack trước, rồi chỉ hỏi đúng thông tin công khai tối thiểu. Khoá nhập vào không được lưu. */
export function SystemScanForm({ initialStack = "supabase", initialRef = "", initialSite = "" }: { initialStack?: Stack; initialRef?: string; initialSite?: string }) {
  const router = useRouter();
  const [stack, setStack] = useState<Stack>(initialStack);
  const [f, setF] = useState({ url: initialStack === "supabase" ? initialRef : "", anonKey: "", tables: "", buckets: "", projectId: initialStack === "firebase" ? initialRef : "", apiKey: "", databaseURL: "", storageBucket: "" });
  const [manual, setManual] = useState(!!initialRef);
  const [site, setSite] = useState(initialSite);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF((p) => ({ ...p, [k]: e.target.value }));

  async function submit() {
    setError(null);
    if (!manual && !site.trim()) return setError("Hãy dán link website của bạn, ví dụ https://ten-ban.com");
    if (manual && stack === "supabase" && (!f.url.trim() || !f.anonKey.trim())) return setError("Hãy nhập địa chỉ dự án và khoá anon (công khai).");
    if (manual && stack === "firebase" && !f.projectId.trim()) return setError("Hãy nhập mã dự án Firebase (Project ID).");
    if (!consent) return setError("Hãy xác nhận bạn là chủ hoặc được phép kiểm tra dự án này.");
    setBusy(true);
    const body = !manual ? { stack: "auto", consent, siteUrl: site.trim() } : stack === "supabase"
      ? { stack, consent, url: f.url.trim(), anonKey: f.anonKey.trim(), tables: split(f.tables), buckets: split(f.buckets) }
      : { stack, consent, projectId: f.projectId.trim(), apiKey: f.apiKey.trim() || undefined, databaseURL: f.databaseURL.trim() || undefined, storageBucket: f.storageBucket.trim() || undefined };
    try {
      const res = await fetch("/api/project-scans/system", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const out = await res.json().catch(() => ({}));
      if (res.status === 401) return router.push("/login?next=/quet-he-thong");
      if (!res.ok) { setError(out.message ?? "Đã xảy ra lỗi. Vui lòng thử lại."); setBusy(false); return; }
      router.push(`/quet-he-thong/${out.id}`);
    } catch { setError("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
  }

  const bind = (k: keyof typeof f) => ({ id: `sys-${k}`, value: f[k], onChange: set(k), disabled: busy });

  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate className="w-full max-w-3xl">
      {!manual && (
        <div>
          <label htmlFor="sys-site" className="eyebrow mb-2 block">dán link website của bạn</label>
          <input id="sys-site" value={site} onChange={(e) => setSite(e.target.value)} disabled={busy} inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={2048} placeholder="https://ten-ban.com" className="input !h-12" />
          <p className="mt-2 text-[13px] leading-relaxed text-muted">Chúng tôi tự đọc website để tìm Supabase hoặc Firebase mà nó đang dùng (các thông tin công khai vốn có sẵn trong trang). Bạn không cần tìm hay dán khoá nào.</p>
          <button type="button" onClick={() => setManual(true)} className="mt-2 text-[13px] text-muted underline hover:text-fg">Không tìm thấy? Nhập thủ công</button>
        </div>
      )}
      {manual && <><button type="button" onClick={() => setManual(false)} className="mb-4 text-[13px] text-muted underline hover:text-fg">← Quay lại dán link website</button>
      <fieldset>
        <legend className="eyebrow mb-2">1 · chọn nơi dự án của bạn chạy</legend>
        <div className="grid gap-2 sm:grid-cols-2">
          {STACKS.map((s) => (
            <label key={s.id} className={`flex cursor-pointer items-center gap-3 rounded-xl border bg-white px-4 py-3 transition-colors ${stack === s.id ? "border-accent bg-accent-soft/60 ring-4 ring-accent/10" : "border-line-strong hover:border-fg/40"}`}>
              <input type="radio" name="stack" value={s.id} checked={stack === s.id} onChange={() => setStack(s.id)} disabled={busy} className="size-4 accent-[var(--color-accent)]" />
              <span><span className="block font-medium">{s.name}</span><span className="block text-[13px] text-muted">{s.hint}</span></span>
            </label>
          ))}
        </div>
        <p className="mt-2 text-[13px] text-faint">Các nền tảng khác (AWS, Appwrite, PocketBase…) sẽ được thêm sau.</p>
      </fieldset>

      <div className="mt-6 space-y-4">
        <p className="eyebrow">2 · thông tin công khai (có sẵn trong code frontend)</p>
        {stack === "supabase" ? (
          <>
            <Field {...bind("url")} label="Địa chỉ dự án" placeholder="https://xxxxxxxxxxxxxxxxxxxx.supabase.co" inputMode="url" maxLength={200} />
            <Field {...bind("anonKey")} label="Khoá anon / publishable" type="password" placeholder="eyJ… hoặc sb_publishable_…" maxLength={2000} hint="Lấy ở Project Settings → API. TUYỆT ĐỐI không dán khoá service_role hay secret: chúng tôi sẽ từ chối và khuyên bạn đổi khoá." />
            <details className="text-sm"><summary className="cursor-pointer text-muted hover:text-fg">Tuỳ chọn: tên bảng / bucket cụ thể</summary>
              <div className="mt-3 space-y-3">
                <Field {...bind("tables")} label="Tên bảng (cách nhau bởi dấu phẩy)" placeholder="orders, customers" hint="Dùng khi Supabase ẩn danh sách bảng. Nếu bỏ trống, chúng tôi thử các tên phổ biến." />
                <Field {...bind("buckets")} label="Tên bucket lưu trữ" placeholder="avatars, documents" hint="Danh sách bucket cần quyền cao hơn nên không tự lấy được." />
              </div>
            </details>
          </>
        ) : (
          <>
            <Field {...bind("projectId")} label="Mã dự án (Project ID)" placeholder="my-app-12345" maxLength={60} hint="Bạn thấy ở Firebase Console → Project settings." />
            <details className="text-sm"><summary className="cursor-pointer text-muted hover:text-fg">Tuỳ chọn: API key, databaseURL, storage bucket</summary>
              <div className="mt-3 space-y-3">
                <Field {...bind("apiKey")} label="API key (công khai)" placeholder="AIza…" maxLength={100} hint="Để kiểm tra giới hạn key và domain đăng nhập." />
                <Field {...bind("databaseURL")} label="databaseURL" placeholder="https://my-app-default-rtdb.firebaseio.com" maxLength={200} />
                <Field {...bind("storageBucket")} label="Storage bucket" placeholder="my-app-12345.appspot.com" maxLength={100} />
              </div>
            </details>
          </>
        )}
      </div>

      </>}

      <div className="panel-soft mt-6 p-4 text-[14px] leading-relaxed">
        <p className="font-medium">Chúng tôi chỉ làm những việc này</p>
        <ul className="mt-1.5 space-y-1 text-muted">
          <li className="flex gap-2"><span className="text-ok" aria-hidden>✓</span>Hỏi dịch vụ của bạn như một người lạ: “tôi có đọc được dữ liệu này không?”</li>
          <li className="flex gap-2"><span className="text-ok" aria-hidden>✓</span>Chỉ dùng thông tin công khai của website. Không cần mật khẩu, không cần quyền quản trị.</li>
          <li className="flex gap-2"><span className="text-ok" aria-hidden>✓</span>Không ghi, sửa, xoá, không tạo tài khoản, không tải nội dung dữ liệu (chỉ đếm).</li>
        </ul>
      </div>

      <label className="mt-4 flex cursor-pointer items-start gap-2 text-sm text-muted">
        <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} disabled={busy} className="mt-0.5 size-4 accent-[var(--color-accent)]" />
        <span>Tôi là chủ của dự án này hoặc được chủ cho phép kiểm tra bảo mật.</span>
      </label>
      <button type="submit" disabled={busy} className="btn-primary btn-lg mt-5">
        {busy ? <><span className="live-dot !bg-white" aria-hidden />Đang kiểm tra…</> : <>Quét hệ thống<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></>}
      </button>
      {error && <p role="alert" className="pop mt-3 flex items-start gap-2 text-sm text-crit"><svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.01" /></svg>{error}</p>}
    </form>
  );
}
