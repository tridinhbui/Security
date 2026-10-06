"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { MatMatSays } from "./matmat/MatMatSays";
import { ScoreRing } from "./motion/ScoreRing";
import { Typed } from "./motion/Typed";

type Status = "pass" | "warning" | "fail";
interface Item { id: string; group?: string; label: string; status: Status; text: string }
interface Result { host: string; score: number; grade: string; counts: Record<Status, number>; items: Item[]; cached?: boolean }

const CHIP: Record<Status, { cls: string; label: string }> = { pass: { cls: "chip-ok", label: "Đạt" }, warning: { cls: "chip-med", label: "Cảnh báo" }, fail: { cls: "chip-crit", label: "Lỗi" } };

/** Các bước Mật Mật “đang làm bên trong” (đúng với các nhóm kiểm tra thật của quét nhanh). Thời gian chỉ mang tính minh hoạ tiến trình. */
const STEPS: { label: string; log: (h: string) => string; say: string }[] = [
  { label: "Tìm địa chỉ máy chủ (DNS)", log: (h) => `dig ${h}`, say: "Mình đang hỏi danh bạ internet xem website này nằm ở đâu 📒" },
  { label: "Gõ cửa HTTPS, xem ổ khoá", log: (h) => `GET https://${h}/`, say: "Giờ mình gõ cửa chính, xem ổ khoá HTTPS có chắc không 🔐" },
  { label: "Thử đi cửa sau (HTTP → HTTPS)", log: (h) => `GET http://${h}/`, say: "Mình thử đi cửa sau xem có được chỉ sang cửa trước không 🚪" },
  { label: "Đọc “biển báo an toàn” (header)", log: () => "đọc header: CSP, nosniff, frame…", say: "Mình đang đọc các biển báo an toàn dán ở cửa 🪧" },
  { label: "Soi cookie và quy tắc CORS", log: () => "kiểm tra Set-Cookie, CORS", say: "Mình xem vé gửi xe (cookie) có tem chống giả chưa 🎟️" },
  { label: "Kiểm tra chữ ký email (SPF/DMARC)", log: (h) => `dig TXT ${h}`, say: "Giờ mình kiểm tra xem ai đó có giả mạo email của bạn được không ✉️" },
  { label: "Tìm thứ lỡ để lộ trong trang", log: () => "quét ghi chú, địa chỉ nội bộ, trang lỗi", say: "Mình đang tìm xem có ghi chú nội bộ nào bị bỏ quên ngoài cửa không 🔍" },
  { label: "Chấm điểm và viết nhận xét", log: () => "tính điểm 0–100", say: "Sắp xong rồi! Mình đang viết nhận xét cho bạn ✍️" },
];
const STEP_MS = 1100;
const MIN_LOADING_MS = STEPS.length * 500;

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

/** Màn hình “đang suy nghĩ”: Mật Mật kể từng bước đang làm, danh sách bước tích dần và khung log như bên trong bộ quét. */
function Thinking({ host, done }: { host: string; done: boolean }) {
  const [step, setStep] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setStep((v) => Math.min(v + 1, STEPS.length - 1)), STEP_MS);
    return () => clearInterval(t);
  }, []);
  const cur = done ? STEPS.length - 1 : step;
  const pct = Math.round(((done ? STEPS.length : cur + 0.5) / STEPS.length) * 100);
  return (
    <div className="panel p-5 sm:p-6" role="status" aria-label="Đang kiểm tra website">
      <MatMatSays text={STEPS[cur]!.say} cps={70} />
      <div className="scanline mt-5 h-1.5 overflow-hidden rounded-full bg-line"><div className="h-full rounded-full bg-accent transition-[width] duration-700 ease-out" style={{ width: `${pct}%` }} /></div>
      <div className="mt-5 grid gap-6 md:grid-cols-[1.1fr_1fr]">
        <ol className="space-y-1">
          {STEPS.map((x, i) => {
            const st = i < cur || done ? "done" : i === cur ? "run" : "wait";
            return (
              <li key={x.label} className={`flex items-center gap-3 rounded-lg px-2.5 py-1.5 text-[14px] transition-colors ${st === "run" ? "bg-accent-soft/70 font-medium" : st === "wait" ? "text-faint" : "text-muted"}`}>
                {st === "done" ? <span className="pop grid size-4 shrink-0 place-items-center rounded-full bg-ok text-white"><svg viewBox="0 0 24 24" className="size-2.5" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"><path d="m5 12.5 4.5 4.5L19 7.5" /></svg></span>
                  : st === "run" ? <span className="spin-ring size-4 shrink-0 rounded-full border-[3px] border-accent/25 border-t-accent" /> : <span className="size-4 shrink-0 rounded-full border-2 border-line-strong" />}
                {x.label}
              </li>
            );
          })}
        </ol>
        <div className="term h-fit self-start" aria-hidden>
          <div className="term-bar"><span className="term-dot" /><span className="term-dot" /><span className="term-dot" /><span className="ml-1">mật-mật ~ bên trong</span></div>
          <div className="term-body space-y-0.5 text-[12.5px]">
            {STEPS.slice(0, cur + 1).slice(-5).map((x, i, arr) => (
              <div key={x.label} className="flex gap-2"><span className="prompt">{i === arr.length - 1 ? "$" : "✓"}</span><span className={i === arr.length - 1 ? "text-fg" : "text-muted"}>{i === arr.length - 1 ? <Typed text={x.log(host)} cps={60} /> : x.log(host)}</span></div>
            ))}
          </div>
        </div>
      </div>
      <p className="mt-4 text-xs text-faint">Mật Mật chỉ đọc những gì ai cũng thấy được, không thay đổi website của bạn.</p>
    </div>
  );
}

/**
 * Gọi /api/quick-scan (backend thật, không dữ liệu giả) rồi hiển thị: điểm 0–100, từng mục Đạt/Cảnh báo/Lỗi bằng tiếng Việt,
 * và lời mời quét đầy đủ. URL người dùng nhập được giữ nguyên trong liên kết đăng ký/đăng nhập để tự điền sau khi vào tài khoản.
 */
export function QuickScanRunner({ url, authed, ruleCount }: { url: string; authed: boolean; ruleCount: number }) {
  const [state, setState] = useState<{ kind: "loading"; done?: boolean } | { kind: "ok"; r: Result } | { kind: "error"; message: string; limited: boolean }>({ kind: "loading" });
  const [selected, setSelected] = useState(0);
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
            <div className="panel reveal grid h-[26rem] overflow-hidden md:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]" style={{ ["--i" as string]: 3 }}>
              <ul className="min-h-0 divide-y divide-line overflow-y-auto border-b border-line md:border-b-0 md:border-r" role="listbox" aria-label="Các mục kiểm tra">
                {r.items.map((i, n) => (
                  <li key={`${n}:${i.id}`} role="option" aria-selected={n === selected}>
                    <button type="button" onClick={() => setSelected(n)} className={`flex w-full items-start gap-3 px-4 py-3 text-left transition-colors ${n === selected ? "bg-accent-soft/70" : "hover:bg-surface"}`}>
                      <span className={`${CHIP[i.status].cls} mt-0.5 w-[5.5rem] shrink-0 justify-center whitespace-nowrap`}>{CHIP[i.status].label}</span>
                      <span className="min-w-0 text-sm"><span className="block font-medium">{i.label}</span><span className="line-clamp-2 text-muted">{i.text}</span></span>
                    </button>
                  </li>
                ))}
              </ul>
              {sel && (
                <div className="min-h-0 overflow-y-auto bg-white p-5" aria-live="polite">
                  <div className="flex items-center gap-2"><span className={CHIP[sel.status].cls}>{CHIP[sel.status].label}</span><h3 className="font-semibold">{sel.label}</h3></div>
                  <p className="mt-3 text-[15px] leading-relaxed text-muted">{sel.text}</p>
                  <MatMatSays key={`${selected}:${sel.id}`} className="mt-5" cps={85} text={`${LIKE[sel.group ?? ""] ?? "Đây là một chỗ trên website mình vừa kiểm tra."}\n${TAIL[sel.status]}`} />
                </div>
              )}
            </div>
          </div>
        );
      })()}
    </section>
  );
}
