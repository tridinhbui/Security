"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { CopyButton } from "./CopyButton";
import { ExportButtons, headline, ProblemPane, TriageStrip } from "./QuickAnalyst";
import { MatMatSays } from "./matmat/MatMatSays";
import { ScanStage } from "./ScanStage";
import { ScoreRing } from "./motion/ScoreRing";
import { Typed } from "./motion/Typed";

type Status = "pass" | "warning" | "fail";
interface Tech { ruleId: string; severity: string; confidence: string; evidence: string[]; owasp: string[]; fixSummary: string; fixSteps: string[]; fix: { label: string; language: string; code: string }[]; references: { title: string; url: string }[]; impact?: { today: string; worst: string; who: string; urgency: "now" | "week" | "later" }; statement?: string; sub?: string; origin?: { kind: string; label: string; meaning: string; rootCause: string }; repro?: string | null }
interface Item { id: string; group?: string; label: string; status: Status; text: string; tech?: Tech }
interface Recon {
  server: string | null; poweredBy: string | null; platforms: string[]; technologies: string[]; addresses: string[]; httpVersion: string | null;
  tls: { protocol: string | null; cipher: string | null; issuer: string | null; subject: string | null; validTo: string | null; daysRemaining: number | null; keyType: string | null; keyBits: number | null; validityDays: number | null; sans: number | null } | null;
  dns: { ns: string[]; mx: string[]; caa: string[]; spf: string | null; dmarc: string | null; dnssec: boolean | null; mtaSts: boolean | null } | null;
  headers: { name: string; value: string | null }[]; cookies: { name: string; flags: string[] }[]; redirects: { status: number | null; url: string }[];
}
const URGENCY: Record<string, { label: string; cls: string }> = { now: { label: "Sửa ngay hôm nay", cls: "chip-crit" }, week: { label: "Sửa trong tuần này", cls: "chip-med" }, later: { label: "Sửa khi rảnh", cls: "chip-info" } };
const SEV: Record<string, string> = { critical: "nghiêm trọng", high: "cao", medium: "trung bình", low: "thấp", info: "thông tin" };
const CONF: Record<string, string> = { high: "cao", medium: "vừa", low: "thấp" };
interface Result { host: string; score: number; grade: string; counts: Record<Status, number>; items: Item[]; cached?: boolean; recon?: Recon }

const CHIP: Record<Status, { cls: string; label: string }> = { pass: { cls: "chip-ok", label: "Đạt" }, warning: { cls: "chip-med", label: "Cảnh báo" }, fail: { cls: "chip-crit", label: "Lỗi" } };

/** Các bước Mật Mật “đang làm bên trong” (bám theo các nhóm kiểm tra thật). Thời gian và số dòng nhật ký chỉ mang tính minh hoạ tiến trình. */
interface Step { label: string; say: string; lines: (h: string) => string[] }
const STEPS: Step[] = [
  { label: "Kiểm tra địa chỉ & chặn mạng nội bộ", say: "Trước hết mình kiểm tra địa chỉ này có phải website công khai không, để không đụng vào mạng nội bộ nào cả 🛡️", lines: (h) => [`validate ${h}`, "scheme=https · port=443 · không có user:pass", "chặn 10/8, 172.16/12, 192.168/16, 169.254/16 ✓"] },
  { label: "Tìm địa chỉ máy chủ (DNS)", say: "Mình đang hỏi danh bạ internet xem website này nằm ở đâu 📒", lines: (h) => [`dig A ${h}`, `dig AAAA ${h}`, "kiểm tra IP trả về có công khai không (chống DNS rebinding)"] },
  { label: "Gõ cửa HTTPS, xem ổ khoá", say: "Giờ mình gõ cửa chính, xem ổ khoá HTTPS có chắc không 🔐", lines: (h) => [`GET https://${h}/`, "đọc status, header, thời gian phản hồi", "xác minh chứng chỉ, tên miền, hạn dùng"] },
  { label: "Thử đi cửa sau (HTTP → HTTPS)", say: "Mình thử đi cửa sau xem có được chỉ sang cửa trước không 🚪", lines: (h) => [`GET http://${h}/`, "theo dõi chuỗi chuyển hướng (tối đa 5 bước)", "có về HTTPS bằng 301/308 không?"] },
  { label: "Đọc “biển báo an toàn” (header)", say: "Mình đang đọc các biển báo an toàn dán ở cửa 🪧", lines: () => ["strict-transport-security ?", "x-content-type-options · x-frame-options ?", "referrer-policy · permissions-policy ?"] },
  { label: "Phân tích chính sách CSP", say: "Mình xem danh sách khách mời (CSP) có chặt không 📋", lines: () => ["parse content-security-policy", "tìm 'unsafe-inline', '*', thiếu object-src/base-uri", "chấm độ chặt của script-src"] },
  { label: "Soi cookie và quy tắc CORS", say: "Mình xem vé gửi xe (cookie) có tem chống giả chưa 🎟️", lines: () => ["đọc Set-Cookie: Secure / HttpOnly / SameSite", "gửi Origin giả lập để xem CORS có mở quá rộng không", "kiểm tra Access-Control-Allow-Origin"] },
  { label: "Phân tích HTML: script, form, nội dung hỗn hợp", say: "Mình đọc trang để xem có tải gì đó qua đường không an toàn không 🔎", lines: () => ["parse HTML: <script>, <form>, <img>, <link>", "tìm http:// lẫn trong trang https", "script từ CDN có integrity (SRI) không?"] },
  { label: "Kiểm tra chữ ký email (SPF/DMARC/CAA)", say: "Giờ mình kiểm tra xem ai đó có giả mạo email của bạn được không ✉️", lines: (h) => [`dig TXT ${h}`, `dig TXT _dmarc.${h}`, `dig CAA ${h}`] },
  { label: "Tìm thứ lỡ để lộ trong trang", say: "Mình đang tìm xem có ghi chú nội bộ nào bị bỏ quên ngoài cửa không 🔍", lines: () => ["quét ghi chú HTML, địa chỉ nội bộ", "thử một đường dẫn không tồn tại để xem trang lỗi", "tìm header gỡ lỗi, phiên bản máy chủ"] },
  { label: "Đọc security.txt và robots.txt", say: "Mình tìm số đường dây nóng bảo mật của website 📞", lines: (h) => [`GET https://${h}/.well-known/security.txt`, `GET https://${h}/robots.txt`, "kiểm tra có là file thật hay trang SPA trả về"] },
  { label: "Chấm điểm và viết nhận xét", say: "Sắp xong rồi! Mình đang chấm điểm và viết nhận xét cho bạn ✍️", lines: () => ["trọng số mức độ × độ tin cậy", "áp trần điểm cho quét nhanh (tối đa 90)", "soạn lời giải thích dễ hiểu cho từng mục"] },
];
const TICK_MS = 430;
const TICKS_PER_STEP = 4;
const MIN_LOADING_MS = STEPS.length * TICKS_PER_STEP * TICK_MS;

const LIKE: Record<string, string> = {
  headers: "Giống các biển báo an toàn dán ở cửa: “đừng đoán loại file”, “đừng nhúng tôi vào khung lạ”.",
  https: "Ổ khoá HTTPS như khoá cửa chính: có thì người đi ngang không nghe lén hay sửa được gì.",
  redirect: "Như bảo vệ chỉ khách đi nhầm cửa sau sang cửa trước có khoá.",
  cookies: "Cookie như vé gửi xe: cần có “tem” chống làm giả thì người lạ mới không lấy được xe.",
  csp: "CSP là danh sách khách mời cho mã chạy trên trang: ai ngoài danh sách bị chặn ở cửa.",
  cors: "CORS quyết định website nào khác được đọc sổ sách của bạn.",
  dns: "SPF/DMARC như chữ ký thư của công ty, để ai mạo danh thì bưu điện biết mà chặn.",
  exposure: "Giống như quên gỡ giấy ghi chú nội bộ dán ngoài cửa tiệm.",
  securitytxt: "security.txt là số đường dây nóng để người phát hiện lỗi biết gọi cho ai.",
  mixed: "Như cửa hàng khoá chắc nhưng vẫn để một cửa sổ mở toang.",
  sri: "SRI là con dấu niêm phong hàng nhập từ nhà cung cấp bên ngoài, bị tráo là biết ngay.",
};
const TAIL: Record<Status, string> = { pass: "Chỗ này bạn làm tốt rồi 🎉", warning: "Chỉ là chỗ nhỏ, sửa khi rảnh nhé.", fail: "Chỗ này nên sửa sớm nha!" };

/** Prompt đơn giản để dán vào AI viết code (Cursor, Claude Code…): chỉ liệt kê các mục chưa đạt, lỗi trước. Ghép chuỗi, không gọi AI. */
function buildPrompt(r: Result): string {
  const bad = r.items.filter((i) => i.status !== "pass");
  return [
    `Bạn là kỹ sư bảo mật. Bộ quét đã kiểm tra ${r.host} và thấy ${bad.length} vấn đề cấu hình cần sửa (xếp từ nghiêm trọng nhất):`,
    "",
    ...bad.map((i, n) => `${n + 1}. [${i.status === "fail" ? "Lỗi" : "Cảnh báo"}] ${i.label}: ${i.text}`),
    "",
    "Hãy làm lần lượt từng vấn đề:",
    "- Tìm đúng file cấu hình hoặc mã trong dự án này (đọc kỹ trước khi sửa, đừng đoán).",
    "- Sửa tối thiểu, không đổi tính năng khác.",
    "- Giải thích ngắn gọn bằng tiếng Việt dễ hiểu bạn đã đổi gì và vì sao.",
    `- Cho mình lệnh để kiểm tra lại sau khi triển khai, ví dụ: curl -sI https://${r.host}`,
  ].join("\n");
}

function CopyPrompt({ r }: { r: Result }) {
  const [ok, setOk] = useState(false);
  return (
    <button type="button" className="btn-primary" onClick={async () => { try { await navigator.clipboard.writeText(buildPrompt(r)); setOk(true); setTimeout(() => setOk(false), 2200); } catch { /* trình duyệt chặn clipboard */ } }}>
      {ok ? "Đã copy ✓ Dán vào Cursor / Claude Code" : "Copy prompt cho AI sửa giúp"}
    </button>
  );
}

function summaryText(r: Result): string {
  const mood = r.score >= 80 ? "Khá ổn đó!" : r.score >= 60 ? "Tạm ổn, còn vài chỗ nên siết lại." : "Còn khá nhiều cửa chưa khoá, mình giúp bạn xem từng chỗ nhé.";
  const bits = [`${r.counts.pass} mục đạt`, r.counts.warning ? `${r.counts.warning} chỗ cần chú ý` : "", r.counts.fail ? `${r.counts.fail} chỗ nên sửa sớm` : ""].filter(Boolean).join(", ");
  return `Xong rồi nè! ${r.host} được ${r.score}/100 điểm (hạng ${r.grade}). ${mood}\nMình thấy: ${bits}. Bấm “Mật Mật giải thích” ở từng mục để hiểu dễ hơn${r.counts.warning + r.counts.fail ? ", rồi copy prompt bên dưới đưa cho AI sửa giúp" : ""} nhé 🐾`;
}

/** Màn hình chia đôi: trái là các bước Mật Mật đang làm, phải là “màn hình trực tiếp” với nhật ký chạy từng dòng. */
function Thinking({ host, done }: { host: string; done: boolean }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((v) => v + 1), TICK_MS);
    return () => clearInterval(t);
  }, []);
  const cur = done ? STEPS.length : Math.min(Math.floor(tick / TICKS_PER_STEP), STEPS.length - 1);
  const into = done ? 0 : tick % TICKS_PER_STEP; // số dòng nhật ký của bước hiện tại đã hiện
  const steps = STEPS.map((x, i) => ({ label: x.label, state: (i < cur ? "done" : i === cur ? "run" : "wait") as "done" | "run" | "wait" }));
  const logs: { text: string; tone: "accent" | "muted" | "ok" }[] = [{ text: `mật-mật scan https://${host}/ --passive`, tone: "accent" }];
  STEPS.forEach((x, i) => {
    if (i > cur) return;
    const ls = x.lines(host);
    if (i < cur) { ls.forEach((t) => logs.push({ text: t, tone: "muted" })); logs.push({ text: `✓ ${x.label}`, tone: "ok" }); }
    else ls.slice(0, Math.min(into + 1, ls.length)).forEach((t) => logs.push({ text: t, tone: "muted" }));
  });
  if (done) logs.push({ text: "Hoàn tất. Đang mở kết quả…", tone: "ok" });
  const frac = done ? 1 : (cur + into / TICKS_PER_STEP) / STEPS.length;
  return <ScanStage host={host} steps={steps} logs={logs} pct={Math.round(frac * 100)} say={STEPS[Math.min(cur, STEPS.length - 1)]!.say} footnote="Mật Mật chỉ đọc những gì ai cũng thấy được, không thay đổi website của bạn." />;
}

/**
 * Gọi /api/quick-scan (backend thật, không dữ liệu giả) rồi hiển thị: điểm 0–100, từng mục Đạt/Cảnh báo/Lỗi bằng tiếng Việt,
 * và lời mời quét đầy đủ. URL người dùng nhập được giữ nguyên trong liên kết đăng ký/đăng nhập để tự điền sau khi vào tài khoản.
 */
/** Cột giải pháp: tóm tắt việc cần làm, các bước, rồi lệnh/cấu hình chép thẳng được. Mục đã đạt thì nói rõ không cần làm gì. */
function Solution({ item, cta }: { item: Item; cta: string }) {
  if (item.status === "pass") {
    return (
      <div className="mt-2 flex items-start gap-2.5 text-[15px] text-muted">
        <svg viewBox="0 0 24 24" className="mt-1 size-4 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m5 12.5 4.5 4.5L19 7.5" /></svg>
        <p>Không cần làm gì thêm cho mục này.</p>
      </div>
    );
  }
  const t = item.tech, fixes = t?.fix ?? [], steps = t?.fixSteps ?? [];
  return (
    <div className="mt-2 space-y-4">
      <p className="text-[15px] font-medium leading-relaxed">{t?.fixSummary || "Sửa theo hướng dẫn bên dưới, rồi quét lại để xác nhận."}</p>
      {steps.length > 0 && <ol className="list-decimal space-y-1.5 pl-5 text-sm leading-relaxed text-muted">{steps.map((s, n) => <li key={n}>{s}</li>)}</ol>}
      {fixes.map((f, n) => (
        <div key={`${n}:${f.label}`}>
          <div className="mb-1.5 flex items-center justify-between gap-2"><p className="text-xs font-medium text-muted">{f.label}</p><CopyButton text={f.code} /></div>
          <pre className="mono max-h-44 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-white p-3 text-[12px] leading-5 text-fg/90">{f.code}</pre>
        </div>
      ))}
      {fixes.length === 0 && steps.length === 0 && <p className="text-sm text-muted">Dùng nút “Copy prompt cho AI” ở trên, hoặc đăng nhập để xem hướng dẫn sửa chi tiết.</p>}
      {fixes.length === 0 && <Link href={cta} className="inline-block text-sm font-medium text-accent hover:underline">Xem hướng dẫn đầy đủ →</Link>}
    </div>
  );
}

/** Tab "Kỹ thuật": dấu vân tay, TLS, DNS, ma trận header, cookie (chỉ tên + cờ), chuỗi chuyển hướng. */
function ReconView({ r }: { r: Recon }) {
  const row = (k: string, v: string | number | boolean | null | undefined) => <div key={k} className="grid grid-cols-[8.5rem_1fr] gap-3 py-1.5 text-sm"><dt className="text-faint">{k}</dt><dd className="mono min-w-0 break-words text-[12.5px]">{v === null || v === undefined || v === "" ? <span className="text-faint">—</span> : String(v)}</dd></div>;
  const card = (title: string, body: React.ReactNode) => <section className="rounded-xl border border-line p-4"><h4 className="eyebrow mb-1">{title}</h4>{body}</section>;
  return (
    <div className="grid gap-4 p-4 lg:grid-cols-2">
      {card("dấu vân tay", <dl>{row("Server", r.server)}{row("X-Powered-By", r.poweredBy)}{row("Nền tảng", r.platforms.join(", "))}{row("Công nghệ", r.technologies.join(", "))}{row("IP", r.addresses.join(", "))}{row("HTTP", r.httpVersion)}</dl>)}
      {card("tls (từ bộ nhớ đệm)", r.tls ? <dl>{row("Giao thức", r.tls.protocol)}{row("Bộ mã hoá", r.tls.cipher)}{row("Nhà cấp", r.tls.issuer)}{row("Khoá", r.tls.keyType ? `${r.tls.keyType} ${r.tls.keyBits ?? ""}` : null)}{row("Còn hạn", r.tls.daysRemaining !== null ? `${r.tls.daysRemaining} ngày` : null)}{row("Thời hạn", r.tls.validityDays !== null ? `${r.tls.validityDays} ngày` : null)}</dl> : <p className="py-2 text-sm text-faint">Chưa có dữ liệu chứng chỉ trong bộ nhớ đệm. Quét đầy đủ để xem.</p>)}
      {card("dns", r.dns ? <dl>{row("NS", r.dns.ns.join(", "))}{row("MX", r.dns.mx.join(", "))}{row("SPF", r.dns.spf)}{row("DMARC", r.dns.dmarc)}{row("CAA", r.dns.caa.join(" | "))}{row("DNSSEC", r.dns.dnssec === null ? null : r.dns.dnssec ? "bật" : "tắt")}{row("MTA-STS", r.dns.mtaSts === null ? null : r.dns.mtaSts ? "có" : "chưa")}</dl> : <p className="py-2 text-sm text-faint">Không tra được DNS.</p>)}
      {card("chuyển hướng http", r.redirects.length ? <ol className="space-y-1 py-1 text-[12.5px]">{r.redirects.map((h, n) => <li key={n} className="mono break-all"><span className="text-faint">{h.status}</span> {h.url}</li>)}</ol> : <p className="py-2 text-sm text-faint">Không có.</p>)}
      <div className="lg:col-span-2">{card("ma trận header", <dl className="divide-y divide-line">{r.headers.map((h) => <div key={h.name} className="grid grid-cols-[13rem_1fr] gap-3 py-1.5 text-sm"><dt className="mono text-[12px] text-muted">{h.name}</dt><dd className="mono min-w-0 break-words text-[12px]">{h.value ?? <span className="text-crit">thiếu</span>}</dd></div>)}</dl>)}</div>
      <div className="lg:col-span-2">{card("cookie (chỉ tên và cờ, không có giá trị)", r.cookies.length ? <ul className="space-y-1 py-1 text-[12.5px]">{r.cookies.map((c) => <li key={c.name} className="mono"><b className="font-semibold">{c.name}</b> <span className="text-muted">{c.flags.join("; ") || "không có cờ"}</span></li>)}</ul> : <p className="py-2 text-sm text-faint">Không đặt cookie khi truy cập ẩn danh.</p>)}</div>
    </div>
  );
}

export function QuickScanRunner({ url, authed, ruleCount }: { url: string; authed: boolean; ruleCount: number }) {
  const [state, setState] = useState<{ kind: "loading"; done?: boolean } | { kind: "ok"; r: Result } | { kind: "error"; message: string; limited: boolean }>({ kind: "loading" });
  const [selected, setSelected] = useState(0);
  const [tab, setTab] = useState<"findings" | "recon">("findings");
  const host = (() => { try { return new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname; } catch { return url; } })();

  useEffect(() => {
    setState({ kind: "loading" });
    setSelected(0);
    const ctl = new AbortController();
    const started = Date.now();
    // Kết quả đến nhanh (nhất là khi có cache) vẫn để Mật Mật “suy nghĩ” đủ lâu cho người dùng theo dõi kịp từng bước.
    const settle = async (next: () => void) => {
      const wait = MIN_LOADING_MS - (Date.now() - started);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      if (ctl.signal.aborted) return;
      setState({ kind: "loading", done: true });
      await new Promise((r) => setTimeout(r, 600));
      if (!ctl.signal.aborted) next();
    };
    (async () => {
      try {
        const res = await fetch("/api/quick-scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }), signal: ctl.signal });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) return void (await settle(() => setState({ kind: "error", message: body.message ?? "Không thể quét lúc này. Vui lòng thử lại sau.", limited: res.status === 429 })));
        await settle(() => setState({ kind: "ok", r: body as Result }));
      } catch (e) {
        if ((e as Error).name !== "AbortError") setState({ kind: "error", message: "Lỗi mạng. Vui lòng thử lại.", limited: false });
      }
    })();
    return () => ctl.abort();
  }, [url]);

  const fullScanPath = `/quet-co-ban?scan=${encodeURIComponent(url)}`;
  const cta = authed ? fullScanPath : `/signup?next=${encodeURIComponent(fullScanPath)}`;

  return (
    <section className="mt-8" aria-live="polite" aria-busy={state.kind === "loading"}>
      {state.kind === "loading" && <Thinking host={host} done={!!state.done} />}

      {state.kind === "error" && (
        <div className="panel p-6" role="alert">
          <p className="font-medium text-crit">Chưa quét được</p>
          <p className="mt-1 text-sm text-muted">{state.message}</p>
          {state.limited && <Link href={cta} className="btn-primary mt-4">Đăng ký để quét tiếp</Link>}
        </div>
      )}

      {state.kind === "ok" && (() => {
        const r = state.r;
        const hasIssue = r.counts.warning + r.counts.fail > 0;
        const sel = r.items[Math.min(selected, r.items.length - 1)];
        return (
          <div className="space-y-4">
            {/* hàng trên: tóm tắt + lời mời quét kỹ hơn nằm cạnh nhau */}
            <div className="grid gap-4 lg:grid-cols-[1.5fr_1fr]">
              <div className="panel reveal p-5 sm:p-6">
                <div className="grid items-center gap-5 sm:grid-cols-[auto_1fr]">
                  <ScoreRing score={r.score} grade={r.grade} size={116} />
                  <div className="min-w-0">
                    <p className="mono truncate text-sm text-muted">{r.host}</p>
                    <div className="mt-2 flex flex-wrap gap-2"><span className="chip-ok">{r.counts.pass} Đạt</span><span className="chip-med">{r.counts.warning} Cảnh báo</span><span className="chip-crit">{r.counts.fail} Lỗi</span></div>
                    {hasIssue && <div className="mt-3"><CopyPrompt r={r} /></div>}
                  </div>
                </div>
                <MatMatSays className="mt-4" text={summaryText(r)} cps={85} />
              </div>

              <div className="panel reveal flex flex-col justify-between gap-4 bg-surface p-5 sm:p-6" style={{ ["--i" as string]: 2 }}>
                <div>
                  <h2 className="text-lg font-semibold tracking-tight">Muốn kiểm tra kỹ hơn?</h2>
                  <p className="mt-1 text-sm text-muted">{authed ? "Chạy" : "Đăng nhập để chạy"} {ruleCount}+ kiểm tra, xem hướng dẫn fix và lưu lịch sử.</p>
                </div>
                <div className="flex flex-col items-start gap-2">
                  <Link href={cta} className="btn-primary">Quét đầy đủ miễn phí<svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M5 12h14M13 6l6 6-6 6" /></svg></Link>
                  {!authed && <Link href={`/login?next=${encodeURIComponent(fullScanPath)}`} className="text-sm text-muted hover:text-fg">Đã có tài khoản? Đăng nhập</Link>}
                  <p className="text-xs text-faint">Quét nhanh chỉ xem trang chủ nên điểm tối đa là 90.{r.cached ? " Kết quả lưu tạm vài giờ." : ""}</p>
                </div>
              </div>
            </div>

            {/* thẻ lớn: danh sách cuộn bên trong + khung xem trước chi tiết */}
            <div className="panel reveal overflow-hidden" style={{ ["--i" as string]: 3 }}>
              <div role="tablist" aria-label="Kết quả" className="flex gap-1 border-b border-line bg-surface px-3 pt-2">
                {([["findings", `Phát hiện (${r.items.length})`], ["recon", "Kỹ thuật"]] as const).map(([k, label]) => (
                  <button key={k} type="button" role="tab" aria-selected={tab === k} onClick={() => setTab(k)} disabled={k === "recon" && !r.recon}
                    className={`rounded-t-lg px-4 py-2 text-sm font-medium transition-colors disabled:opacity-40 ${tab === k ? "bg-white text-fg shadow-crisp" : "text-muted hover:text-fg"}`}>{label}</button>
                ))}
                <div className="ml-auto self-center pb-1"><ExportButtons result={r} /></div>
              </div>
              {tab === "findings" && <TriageStrip items={r.items} />}
              {tab === "recon" && r.recon ? <div className="h-[30rem] overflow-y-auto"><ReconView r={r.recon} /></div> : (
              <div className="grid h-[44rem] md:grid-cols-[minmax(0,.9fr)_minmax(0,1.6fr)] lg:h-[36rem] lg:grid-cols-[minmax(0,.8fr)_minmax(0,1fr)_minmax(0,1.1fr)]">
                <ul className="min-h-0 divide-y divide-line overflow-y-auto border-b border-line md:border-b-0 md:border-r" role="listbox" aria-label="Các mục kiểm tra">
                  {r.items.map((i, n) => (
                    <li key={`${n}:${i.id}`} role="option" aria-selected={n === selected}>
                      <button type="button" onClick={() => setSelected(n)} className={`flex w-full items-start gap-3 px-4 py-3 text-left transition-colors ${n === selected ? "bg-accent-soft/70" : "hover:bg-surface"}`}>
                        <span className={`${CHIP[i.status].cls} mt-0.5 w-[5.5rem] shrink-0 justify-center whitespace-nowrap`}>{CHIP[i.status].label}</span>
                        <span className="min-w-0 text-sm"><span className="block font-medium leading-snug">{headline(i).title}</span><span className="line-clamp-2 text-muted">{i.status === "pass" ? i.text : headline(i).sub}</span></span>
                      </button>
                    </li>
                  ))}
                </ul>
                {sel && (
                  <div className="grid min-h-0 grid-rows-[minmax(0,1fr)_minmax(0,1fr)] overflow-hidden lg:col-span-2 lg:grid-cols-2 lg:grid-rows-1" aria-live="polite">
                    {/* vấn đề */}
                    <div className="min-h-0 overflow-y-auto bg-white p-5">
                      <ProblemPane item={sel} />
                      <MatMatSays key={`${selected}:${sel.id}`} className="mt-4" cps={85} text={`${LIKE[sel.group ?? ""] ?? "Đây là một chỗ trên website mình vừa kiểm tra."}\n${TAIL[sel.status]}`} />
                    </div>
                    {/* giải pháp: luôn hiện, song song với vấn đề */}
                    <div className="min-h-0 overflow-y-auto border-t border-line bg-accent-soft/40 p-5 lg:border-l lg:border-t-0">
                      <p className="eyebrow !text-accent">giải pháp</p>
                      <Solution item={sel} cta={cta} />
                    </div>
                  </div>
                )}
              </div>)}
            </div>
          </div>
        );
      })()}
    </section>
  );
}
