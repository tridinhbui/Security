"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

/** Ô nhập kho GitHub. Token (chỉ khi kho riêng tư) chỉ gửi cho đúng lượt quét này, không được lưu. */
interface RepoOpt { name: string; private: boolean }

export function CodeScanForm({ initialRepo = "", githubEnabled = false, connected = false }: { initialRepo?: string; githubEnabled?: boolean; connected?: boolean }) {
  const router = useRouter();
  const [repo, setRepo] = useState(initialRepo);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [isConnected, setConnected] = useState(connected);
  const [repos, setRepos] = useState<RepoOpt[]>([]);
  useEffect(() => {
    if (!isConnected) return;
    fetch("/api/github/repos").then(async (r) => {
      if (r.ok) setRepos(((await r.json()) as { repos: RepoOpt[] }).repos);
      else { setConnected(false); setError("Phiên kết nối GitHub đã hết hạn. Hãy kết nối lại."); }
    }).catch(() => undefined);
  }, [isConnected]);
  async function disconnect() { await fetch("/api/github/disconnect", { method: "POST" }).catch(() => undefined); setConnected(false); setRepos([]); }

  async function submit() {
    if (!repo.trim()) return setError("Hãy nhập kho GitHub, ví dụ: vercel/next.js");
    setBusy(true); setError(null);
    try {
      const res = await fetch("/api/project-scans/code", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo: repo.trim(), token: isConnected ? undefined : token.trim() || undefined, useConnected: isConnected || undefined }) });
      const body = await res.json().catch(() => ({}));
      if (res.status === 401) return router.push("/login?next=/quet-ma-nguon");
      if (!res.ok) { setError(body.message ?? "Đã xảy ra lỗi. Vui lòng thử lại."); setBusy(false); return; }
      router.push(`/quet-ma-nguon/${body.id}`);
    } catch { setError("Lỗi mạng. Vui lòng thử lại."); setBusy(false); }
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); void submit(); }} noValidate className="w-full">
      <div className={`flex flex-col gap-2 rounded-2xl border bg-white p-2 shadow-glow transition-[border-color,box-shadow] duration-200 focus-within:border-accent focus-within:ring-4 focus-within:ring-accent/15 sm:flex-row sm:items-center ${error ? "border-crit/50" : "border-line-strong"}`}>
        <label className="sr-only" htmlFor="repo">Kho GitHub</label>
        <div className="flex min-w-0 flex-1 items-center gap-3 px-3">
          <svg viewBox="0 0 24 24" className="size-5 shrink-0 text-fg" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16" /></svg>
          <input id="repo" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="Kho GitHub (ví dụ: ten-ban/du-an)" value={repo} onChange={(e) => setRepo(e.target.value)} disabled={busy} maxLength={300}
            aria-invalid={!!error} aria-describedby={error ? "repo-error" : undefined} className="h-12 min-w-0 flex-1 bg-transparent text-[15px] text-fg placeholder:text-faint focus:outline-none" />
        </div>
        <button type="submit" disabled={busy} className="btn-primary btn-lg sm:min-w-36">
          {busy ? <><span className="live-dot !bg-white" aria-hidden />Đang quét…</> : <>Quét mã nguồn<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></>}
        </button>
      </div>
      {githubEnabled && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          {isConnected ? (
            <>
              <span className="chip-ok">đã kết nối GitHub</span>
              {repos.length > 0 && (
                <select aria-label="Chọn repo" value="" onChange={(e) => e.target.value && setRepo(e.target.value)} disabled={busy} className="input !h-9 !w-auto max-w-full !text-[14px]">
                  <option value="">Chọn từ repo của bạn…</option>
                  {repos.map((r) => <option key={r.name} value={r.name}>{r.name}{r.private ? " 🔒" : ""}</option>)}
                </select>
              )}
              <button type="button" onClick={disconnect} className="text-[13px] text-muted underline hover:text-fg">Ngắt kết nối</button>
            </>
          ) : (
            <>
              <a href="/api/github/connect" className="btn-ghost btn-sm">Kết nối GitHub</a>
              <span className="text-[13px] text-muted">để chọn repo (kể cả riêng tư). Chỉ đọc, kết nối hết hạn sau 1 giờ.</span>
            </>
          )}
        </div>
      )}
      {!isConnected && <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-muted hover:text-fg">Kho riêng tư? Dùng token chỉ-đọc</summary>
        <div className="panel-soft mt-2 space-y-2 p-4">
          <label htmlFor="gh-token" className="block text-[13px] font-medium">Token GitHub (fine-grained, chỉ quyền “Contents: Read-only” cho đúng kho này)</label>
          <input id="gh-token" type="password" autoComplete="off" spellCheck={false} placeholder="github_pat_…" value={token} onChange={(e) => setToken(e.target.value)} disabled={busy} maxLength={300} className="input" />
          <p className="text-[13px] leading-relaxed text-muted">Token chỉ dùng cho lượt quét này rồi bỏ đi, không được lưu hay ghi lại. Bạn có thể thu hồi nó ngay sau khi quét ở GitHub → Settings → Developer settings.</p>
        </div>
      </details>}
      {busy && <p className="mt-3 text-sm text-muted" role="status">Đang tải và đọc mã nguồn, thường mất 10–40 giây tuỳ kích thước kho…</p>}
      {error && <p id="repo-error" role="alert" className="pop mt-3 flex items-start gap-2 text-sm text-crit"><svg viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" aria-hidden><circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16.5v.01" /></svg>{error}</p>}
    </form>
  );
}
