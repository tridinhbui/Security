import type { Severity } from "../scanner/types";
import { item, type ProjectItem } from "./types";

/**
 * Quét hệ thống (backend) — CHỈ ĐỌC, KHÔNG KHAI THÁC. Chỉ dùng khoá CÔNG KHAI mà ứng dụng frontend vốn đã gửi cho mọi khách
 * (Supabase anon/publishable, Firebase API key) để xem một người lạ "đứng ngoài" làm được gì. Không ghi/sửa/xoá, không đăng ký tài khoản,
 * không đọc nội dung dữ liệu (chỉ đếm dòng bằng HEAD / liệt kê khoá). Tên miền đích bị khoá cứng theo từng dịch vụ để không thể dùng làm SSRF.
 */

export class SystemScanError extends Error { constructor(readonly code: "invalid_input" | "service_role" | "key_mismatch", message: string) { super(message); } }

const G_DB = "Dữ liệu (database)", G_STORAGE = "Tệp lưu trữ (storage)", G_AUTH = "Đăng nhập (auth)", G_API = "API & CORS", G_KEY = "Khoá bảo mật";

interface Probe { status: number; headers: Headers; body: string; json: unknown }
type Fetcher = typeof fetch;

async function probe(f: Fetcher, url: string, init: RequestInit = {}): Promise<Probe | null> {
  try {
    const res = await f(url, { redirect: "manual", signal: AbortSignal.timeout(8_000), ...init, headers: { "User-Agent": "VibeSec-Scanner", ...(init.headers as Record<string, string> | undefined) } });
    const body = init.method === "HEAD" ? "" : (await res.text()).slice(0, 200_000);
    let json: unknown = null;
    try { json = body ? JSON.parse(body) : null; } catch { /* không phải JSON */ }
    return { status: res.status, headers: res.headers, body, json };
  } catch { return null; }
}

const decodeJwt = (jwt: string): Record<string, unknown> | null => {
  const p = jwt.split(".");
  if (p.length !== 3) return null;
  try { const o = JSON.parse(atob(p[1]!.replace(/-/g, "+").replace(/_/g, "/"))); return o && typeof o === "object" ? o : null; } catch { return null; }
};
const SENSITIVE_TABLE = /user|profile|account|customer|order|payment|invoice|message|chat|email|address|member|subscription|token|session|secret|admin|contact|patient|booking|ticket/i;
const COMMON_TABLES = ["users", "profiles", "accounts", "customers", "orders", "payments", "messages", "posts", "comments", "todos", "items", "products", "bookings", "subscriptions", "documents", "files", "notes", "tasks", "projects", "teams", "invoices", "leads", "contacts", "chats", "orgs"];
const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const BUCKET_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$/;

// ================================================================== Supabase

export interface SupabaseInput { url: string; anonKey: string; tables?: string[]; buckets?: string[] }

/** Chấp nhận mã dự án (20 ký tự) hoặc URL https://<ref>.supabase.co. Từ chối mọi tên miền khác. */
export function parseSupabaseRef(input: string): string | null {
  const s = input.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0]!;
  const m = s.match(/^([a-z0-9]{20})(?:\.supabase\.(?:co|in))?$/);
  return m ? m[1]! : null;
}

const RLS_SQL = (t: string) => `alter table public."${t}" enable row level security;\n\n-- Ví dụ: mỗi người chỉ đọc được dòng của chính mình\ncreate policy "chi doc du lieu cua minh" on public."${t}"\n  for select to authenticated using (auth.uid() = user_id);`;

export async function scanSupabase(input: SupabaseInput, f: Fetcher = fetch): Promise<{ label: string; items: ProjectItem[] }> {
  const ref = parseSupabaseRef(input.url);
  if (!ref) throw new SystemScanError("invalid_input", "Hãy nhập địa chỉ dự án Supabase dạng https://xxxxxxxxxxxxxxxxxxxx.supabase.co (hoặc mã dự án 20 ký tự).");
  const key = input.anonKey.trim();
  if (!key) throw new SystemScanError("invalid_input", "Hãy dán khoá \"anon\" (hoặc \"publishable\") của dự án, là khoá công khai có sẵn trong code frontend.");
  if (key.startsWith("sb_secret_")) throw new SystemScanError("service_role", "Đây là khoá bí mật (secret). Chúng tôi không dùng và không cần khoá này. Hãy tạo lại khoá trong Supabase vì bạn vừa dán nó ra ngoài, rồi dùng khoá anon/publishable.");
  const jwt = key.startsWith("sb_publishable_") ? null : decodeJwt(key);
  if (!key.startsWith("sb_publishable_") && !jwt) throw new SystemScanError("invalid_input", "Khoá không đúng định dạng. Hãy dùng khoá anon (bắt đầu bằng eyJ…) hoặc publishable (sb_publishable_…).");
  if (jwt?.role === "service_role") throw new SystemScanError("service_role", "Đây là khoá service_role có toàn quyền với database. Chúng tôi không dùng và không cần khoá này. Hãy tạo lại khoá trong Supabase (Project Settings → API) vì bạn vừa dán nó ra ngoài, rồi dùng khoá anon.");
  if (jwt && jwt.role !== "anon") throw new SystemScanError("invalid_input", "Khoá này không phải khoá anon. Hãy dùng khoá \"anon public\" trong Project Settings → API.");
  if (jwt && typeof jwt.ref === "string" && jwt.ref !== ref) throw new SystemScanError("key_mismatch", "Khoá anon thuộc dự án khác với địa chỉ bạn nhập. Hãy kiểm tra lại cho đúng cặp.");

  const base = `https://${ref}.supabase.co`;
  const H: Record<string, string> = { apikey: key, ...(jwt ? { Authorization: `Bearer ${key}` } : {}) };
  const items: ProjectItem[] = [];

  // --- Auth
  const au = await probe(f, `${base}/auth/v1/settings`, { headers: H });
  const as = au?.status === 200 && au.json && typeof au.json === "object" ? (au.json as Record<string, unknown>) : null;
  if (!as) items.push(item({ id: "sb-auth-settings", group: G_AUTH, source: "system", title: "Chưa đọc được cấu hình đăng nhập", severity: "info", status: "unknown", summary: "Không lấy được cài đặt Auth bằng khoá công khai (có thể khoá sai hoặc dự án đang tạm dừng).", why: "Cấu hình đăng nhập quyết định ai có thể tạo tài khoản và truy cập dữ liệu." }));
  else {
    const external = (as.external ?? {}) as Record<string, boolean>;
    if (as.mailer_autoconfirm === true) items.push(item({ id: "sb-auth-autoconfirm", group: G_AUTH, source: "system", title: "Đăng ký không cần xác nhận email", severity: "medium", status: "fail", summary: "Ai cũng có thể tạo tài khoản bằng email bất kỳ (kể cả email của người khác) và dùng ngay mà không cần bấm link xác nhận.", why: "Kẻ xấu tạo hàng loạt tài khoản giả và nếu bảng của bạn cho phép \"mọi người đã đăng nhập\" thì họ đọc được dữ liệu.", fix: { summary: "Bật bắt buộc xác nhận email.", steps: ["Vào Supabase → Authentication → Providers → Email.", "Bật \"Confirm email\".", "Với bảng quan trọng, đừng chỉ cho phép \"mọi người đã đăng nhập\": giới hạn theo auth.uid()."] }, evidence: ["mailer_autoconfirm = true"] }));
    else items.push(item({ id: "sb-auth-autoconfirm", group: G_AUTH, source: "system", title: "Đăng ký yêu cầu xác nhận email", severity: "info", status: "pass", summary: "Tài khoản mới phải xác nhận email trước khi dùng.", why: "Chặn tài khoản giả hàng loạt." }));
    const open = as.disable_signup === false;
    items.push(item({ id: "sb-auth-signup", group: G_AUTH, source: "system", title: open ? "Ai cũng có thể tự đăng ký tài khoản" : "Đăng ký tự do đã tắt", severity: "info", status: "info", summary: open ? "Đăng ký công khai đang bật. Bình thường với ứng dụng cho khách, nhưng đừng coi \"đã đăng nhập\" là \"đáng tin\"." : "Chỉ người được mời mới có tài khoản.", why: "Quyết định mức tin cậy bạn nên đặt cho người dùng đã đăng nhập.", evidence: [`Phương thức bật: ${Object.entries(external).filter(([, v]) => v).map(([k]) => k).join(", ") || "không rõ"}`] }));
  }

  // --- Cấu trúc API / bảng
  const spec = await probe(f, `${base}/rest/v1/`, { headers: { ...H, Accept: "application/openapi+json" } });
  const sj = spec?.status === 200 && spec.json && typeof spec.json === "object" ? (spec.json as { paths?: Record<string, unknown> }) : null;
  const specPaths = Object.keys(sj?.paths ?? {});
  const specTables = specPaths.filter((p) => /^\/[A-Za-z_]\w*$/.test(p)).map((p) => p.slice(1));
  const rpcs = specPaths.filter((p) => p.startsWith("/rpc/")).map((p) => p.slice(5));
  if (sj) items.push(item({ id: "sb-schema-exposed", group: G_API, source: "system", title: "Cấu trúc database (tên bảng, cột) đọc được công khai", severity: "low", status: "fail", summary: `Bất kỳ ai có khoá công khai đều xem được danh sách ${specTables.length} bảng và các cột. Đây là thông tin giúp kẻ tấn công biết nên thử vào đâu.`, why: "Không trực tiếp lộ dữ liệu nhưng giúp kẻ xấu nhắm đúng bảng nhạy cảm.", fix: { summary: "Chỉ để lộ những bảng thật sự cần cho ứng dụng.", steps: ["Chuyển bảng nội bộ sang schema riêng (không nằm trong \"Exposed schemas\").", "Vào Project Settings → API → Exposed schemas và chỉ giữ lại schema cần thiết."] }, evidence: cap(specTables, 8) }));
  else items.push(item({ id: "sb-schema-exposed", group: G_API, source: "system", title: "Cấu trúc database không bị lộ công khai", severity: "info", status: "pass", summary: "Khoá công khai không đọc được danh sách bảng.", why: "Giảm thông tin cho kẻ tấn công." }));
  if (rpcs.length) items.push(item({ id: "sb-rpc-exposed", group: G_API, source: "system", title: `Có ${rpcs.length} hàm (RPC) gọi được từ trình duyệt`, severity: "low", status: "info", summary: "Chúng tôi KHÔNG chạy thử các hàm này vì chúng có thể thay đổi dữ liệu. Hãy tự kiểm tra từng hàm có kiểm tra quyền người gọi.", why: "Hàm chạy với quyền cao (security definer) mà không kiểm tra người gọi có thể bỏ qua toàn bộ RLS.", fix: { summary: "Xem lại từng hàm, thu hồi quyền chạy của anon nếu không cần.", snippet: { label: "Thu hồi quyền gọi hàm với người lạ", language: "sql", code: "revoke execute on function public.ten_ham(...) from anon, public;" } }, evidence: cap(rpcs, 8) }));

  // --- Quyền đọc từng bảng (HEAD + đếm: không tải nội dung)
  const userTables = (input.tables ?? []).filter((t) => TABLE_RE.test(t)).slice(0, 30);
  const candidates = [...new Set([...userTables, ...(specTables.length ? specTables : COMMON_TABLES)])].slice(0, 60);
  const results = await mapPool(candidates, 6, async (t) => {
    const r = await probe(f, `${base}/rest/v1/${encodeURIComponent(t)}?select=*`, { method: "HEAD", headers: { ...H, Prefer: "count=exact", "Range-Unit": "items", Range: "0-0" } });
    if (!r || (r.status !== 200 && r.status !== 206)) return { t, state: r?.status === 404 ? "absent" as const : "denied" as const, rows: 0 };
    const total = r.headers.get("content-range")?.split("/")[1];
    const rows = total && total !== "*" ? Number(total) : 0;
    return { t, state: rows > 0 ? "open" as const : "empty" as const, rows };
  });
  const open = results.filter((r) => r.state === "open");
  const checked = results.filter((r) => r.state !== "absent");
  for (const r of open.slice(0, 12)) items.push(item({
    id: `sb-table-open:${r.t}`, group: G_DB, source: "system", title: `Bảng "${r.t}" đọc được bởi bất kỳ ai`, severity: SENSITIVE_TABLE.test(r.t) ? "critical" : "high", status: "fail",
    summary: `Chỉ với khoá công khai (không cần đăng nhập), chúng tôi thấy có ${r.rows.toLocaleString("vi-VN")} dòng dữ liệu trong bảng này. Chúng tôi chỉ đếm, không tải nội dung.`,
    why: "Khoá công khai có trong code của website, ai cũng lấy được. Nếu bảng chưa bật RLS (Row Level Security), người lạ đọc được toàn bộ dữ liệu — và thường cả sửa/xoá.",
    fix: { summary: `Bật Row Level Security cho bảng "${r.t}" và chỉ cho phép đúng người xem.`, steps: ["Vào Supabase → SQL Editor, chạy lệnh bên dưới (sửa cột user_id cho đúng bảng của bạn).", "Kiểm tra lại ứng dụng vẫn hoạt động: người dùng chỉ thấy dữ liệu của chính họ.", "Quét lại để xác nhận."], snippet: { label: "Bật RLS", language: "sql", code: RLS_SQL(r.t) } },
    evidence: [`HEAD /rest/v1/${r.t} → đọc được ${r.rows} dòng với vai trò anon`], technical: "PostgREST: Prefer count=exact + Range 0-0; chỉ đọc header Content-Range.",
  }));
  if (open.length > 12) items.push(item({ id: "sb-table-open:more", group: G_DB, source: "system", title: `Và ${open.length - 12} bảng khác đọc được công khai`, severity: "high", status: "fail", summary: "Danh sách quá dài. Bật RLS cho mọi bảng trong schema public.", why: "Mọi bảng chưa bật RLS đều lộ dữ liệu.", fix: { summary: "Liệt kê bảng chưa bật RLS và bật lần lượt.", snippet: { label: "Bảng chưa bật RLS", language: "sql", code: "select tablename from pg_tables where schemaname = 'public' and not rowsecurity;" } }, evidence: cap(open.slice(12).map((r) => r.t), 10) }));
  if (!open.length) items.push(item({ id: "sb-tables-clean", group: G_DB, source: "system", title: "Không bảng nào đọc được bằng khoá công khai", severity: "info", status: "pass", summary: `Đã thử ${checked.length} bảng${specTables.length ? "" : " (tên phổ biến và tên bạn nhập, vì danh sách bảng đang được ẩn)"}: người lạ không đọc được dòng dữ liệu nào.`, why: "Đây là dấu hiệu RLS đang hoạt động đúng.", evidence: specTables.length ? [] : ["Lưu ý: bảng có tên khác ngoài danh sách thử không được kiểm tra. Nhập thêm tên bảng ở mục \"Tuỳ chọn\"."] }));
  items.push(item({
    id: "sb-write-unchecked", group: G_DB, source: "system", title: "Quyền ghi / sửa / xoá chưa được kiểm tra", severity: "medium", status: "unknown",
    summary: "Chúng tôi không thử ghi, sửa hay xoá dữ liệu của bạn nên không thể xác nhận người lạ KHÔNG ghi được. Hãy tự xem lại policy bằng truy vấn bên dưới.", why: "Một bảng chỉ cho đọc nhưng lỡ cho phép ghi vẫn có thể bị phá hoại.",
    fix: { summary: "Xem toàn bộ policy và bảng chưa bật RLS.", snippet: { label: "Kiểm tra trong SQL Editor", language: "sql", code: "-- Bảng chưa bật RLS\nselect tablename from pg_tables where schemaname = 'public' and not rowsecurity;\n\n-- Các policy đang có\nselect tablename, policyname, cmd, roles, qual, with_check from pg_policies where schemaname = 'public';" } },
  }));

  // --- Storage
  const bl = await probe(f, `${base}/storage/v1/bucket`, { headers: H });
  const bucketList = bl?.status === 200 && Array.isArray(bl.json) ? (bl.json as { name: string; public?: boolean }[]) : null;
  const names = new Map<string, boolean | null>();
  for (const b of bucketList ?? []) names.set(b.name, !!b.public);
  for (const b of (input.buckets ?? []).filter((x) => BUCKET_RE.test(x)).slice(0, 15)) if (!names.has(b)) names.set(b, null);
  const bucketRes = await mapPool([...names.keys()], 4, async (name) => {
    const ls = await probe(f, `${base}/storage/v1/object/list/${encodeURIComponent(name)}`, { method: "POST", headers: { ...H, "content-type": "application/json" }, body: JSON.stringify({ prefix: "", limit: 1, offset: 0 }) });
    const listing = ls?.status === 200 && Array.isArray(ls.json) && (ls.json as unknown[]).length > 0;
    let isPublic = names.get(name);
    if (isPublic === null || isPublic === undefined) {
      const pu = await probe(f, `${base}/storage/v1/object/public/${encodeURIComponent(name)}/vibesec-probe-nonexistent`, { headers: H });
      isPublic = /object not found/i.test(pu?.body ?? "") ? true : /bucket not found/i.test(pu?.body ?? "") ? false : null;
    }
    return { name, isPublic, listing };
  });
  for (const b of bucketRes) {
    if (b.listing) items.push(item({ id: `sb-bucket-listing:${b.name}`, group: G_STORAGE, source: "system", title: `Bucket "${b.name}" cho phép liệt kê toàn bộ file`, severity: "high", status: "fail", summary: "Người lạ xem được danh sách tên file trong bucket này (chúng tôi chỉ xem 1 mục, không tải file).", why: "Khi tên file bị lộ, kẻ xấu tải hàng loạt: ảnh giấy tờ, hoá đơn, bản sao lưu…", fix: { summary: "Gỡ policy cho phép SELECT với mọi người trên storage.objects của bucket này, hoặc chuyển bucket sang riêng tư.", steps: ["Vào Supabase → Storage → Policies.", "Xoá policy SELECT cho vai trò anon/public trên bucket này nếu không cần.", "Nếu file cần hiển thị công khai, giữ bucket public nhưng đừng cho phép liệt kê."] }, evidence: [`POST /storage/v1/object/list/${b.name} → có file`] }));
    else if (b.isPublic) items.push(item({ id: `sb-bucket-public:${b.name}`, group: G_STORAGE, source: "system", title: `Bucket "${b.name}" là công khai`, severity: "medium", status: "fail", confidence: "medium", summary: "Ai có đường dẫn file đều tải được, không cần đăng nhập. Ổn nếu chỉ chứa ảnh đại diện/ảnh sản phẩm; nguy hiểm nếu chứa tài liệu riêng.", why: "Đường dẫn công khai có thể bị lan truyền hoặc đoán ra.", fix: { summary: "Nếu bucket chứa dữ liệu riêng tư, chuyển sang riêng tư và dùng signed URL.", steps: ["Vào Storage → bucket → Edit bucket → tắt \"Public bucket\".", "Trong code, dùng createSignedUrl() để tạo link có hạn cho người được phép."] }, evidence: [] }));
  }
  if (bucketRes.length && !bucketRes.some((b) => b.listing || b.isPublic)) items.push(item({ id: "sb-storage-clean", group: G_STORAGE, source: "system", title: "Không thấy bucket công khai hay liệt kê được", severity: "info", status: "pass", summary: `Đã thử ${bucketRes.length} bucket.`, why: "File không bị lộ cho người lạ." }));
  if (!bucketList) items.push(item({ id: "sb-storage-unknown", group: G_STORAGE, source: "system", title: "Chưa thể liệt kê bucket tự động", severity: "info", status: "unknown", summary: bucketRes.length ? "Danh sách bucket cần quyền cao hơn khoá công khai, nên chỉ các bucket bạn nhập được kiểm tra." : "Danh sách bucket cần quyền cao hơn khoá công khai. Nhập tên bucket ở mục \"Tuỳ chọn\" để kiểm tra từng cái.", why: "Bucket công khai chứa file nhạy cảm là lỗi rất hay gặp." }));

  // --- GraphQL introspection
  const gq = await probe(f, `${base}/graphql/v1`, { method: "POST", headers: { ...H, "content-type": "application/json" }, body: JSON.stringify({ query: "{__schema{queryType{name}}}" }) });
  if (gq?.status === 200 && JSON.stringify(gq.json ?? "").includes("queryType")) items.push(item({ id: "sb-graphql-introspection", group: G_API, source: "system", title: "GraphQL cho phép xem toàn bộ cấu trúc dữ liệu", severity: "low", status: "fail", summary: "Điểm cuối /graphql/v1 trả về cấu trúc schema cho người lạ.", why: "Giúp kẻ tấn công vẽ bản đồ database của bạn.", fix: { summary: "Nếu không dùng GraphQL, tắt tiện ích pg_graphql.", snippet: { label: "Tắt pg_graphql", language: "sql", code: "drop extension if exists pg_graphql;" } }, evidence: [] }));

  // --- CORS
  const cors = await probe(f, `${base}/rest/v1/`, { method: "OPTIONS", headers: { ...H, Origin: "https://vibesec-cors-check.invalid", "Access-Control-Request-Method": "GET" } });
  const acao = cors?.headers.get("access-control-allow-origin") ?? null, acac = cors?.headers.get("access-control-allow-credentials") ?? null;
  if (cors && acao === "https://vibesec-cors-check.invalid" && acac === "true") items.push(item({ id: "sb-cors", group: G_API, source: "system", title: "API chấp nhận yêu cầu có đăng nhập từ website bất kỳ", severity: "high", status: "fail", summary: "API phản chiếu mọi website và cho phép gửi kèm cookie.", why: "Website lạ có thể đọc dữ liệu thay mặt người dùng đang đăng nhập.", fix: { summary: "Chỉ cho phép tên miền của bạn." }, evidence: [`Access-Control-Allow-Origin: ${acao}`, "Access-Control-Allow-Credentials: true"] }));
  else if (cors) items.push(item({ id: "sb-cors", group: G_API, source: "system", title: "CORS: API công khai cho mọi website (bình thường với Supabase)", severity: "info", status: "pass", summary: acao === "*" ? "API cho phép mọi website gọi bằng khoá công khai, không kèm cookie. Đây là mặc định của Supabase; an toàn dựa vào RLS." : "Không thấy cấu hình CORS nguy hiểm.", why: "CORS không thay thế được phân quyền dữ liệu, RLS mới là lớp bảo vệ chính.", evidence: acao ? [`Access-Control-Allow-Origin: ${acao}`] : [] }));

  items.push(item({ id: "sb-key-public", group: G_KEY, source: "system", title: "Dùng đúng khoá công khai", severity: "info", status: "pass", summary: "Khoá bạn dán là khoá công khai (anon/publishable). Khoá service_role chưa bị dán vào đây.", why: "Khoá service_role chỉ được tồn tại trên máy chủ." }));
  return { label: ref, items };
}

// ================================================================== Firebase

export interface FirebaseInput { projectId: string; apiKey?: string; databaseURL?: string; storageBucket?: string }
const PID = /^[a-z][a-z0-9-]{4,29}$/;
const RTDB_HOST = /^[a-z0-9-]{3,63}\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)$/;
const FB_BUCKET = /^[a-z0-9][a-z0-9._-]{2,62}$/;

export async function scanFirebase(input: FirebaseInput, f: Fetcher = fetch): Promise<{ label: string; items: ProjectItem[] }> {
  const pid = input.projectId.trim().toLowerCase();
  if (!PID.test(pid)) throw new SystemScanError("invalid_input", "Mã dự án Firebase không hợp lệ (ví dụ: my-app-12345). Bạn thấy nó trong Project settings.");
  const apiKey = input.apiKey?.trim() || "";
  if (apiKey && !/^AIza[0-9A-Za-z_-]{35}$/.test(apiKey)) throw new SystemScanError("invalid_input", "API key Firebase không đúng định dạng (bắt đầu bằng AIza…).");
  let dbHost: string | null = null;
  if (input.databaseURL?.trim()) {
    try { const u = new URL(input.databaseURL.trim()); if (u.protocol === "https:" && RTDB_HOST.test(u.hostname)) dbHost = u.hostname; } catch { /* sai định dạng */ }
    if (!dbHost) throw new SystemScanError("invalid_input", "databaseURL không hợp lệ (ví dụ: https://my-app-default-rtdb.firebaseio.com).");
  }
  const bucketIn = input.storageBucket?.trim().replace(/^gs:\/\//, "");
  if (bucketIn && !FB_BUCKET.test(bucketIn)) throw new SystemScanError("invalid_input", "Tên storage bucket không hợp lệ (ví dụ: my-app-12345.appspot.com).");
  const items: ProjectItem[] = [];

  // --- Realtime Database
  const hosts = dbHost ? [dbHost] : [`${pid}-default-rtdb.firebaseio.com`, `${pid}.firebaseio.com`];
  let rtdb: "open" | "closed" | "none" = "none";
  for (const h of hosts) {
    const r = await probe(f, `https://${h}/.json?shallow=true`);
    if (!r) continue;
    if (r.status === 200) {
      const keys = r.json && typeof r.json === "object" ? Object.keys(r.json as object) : [];
      items.push(item({ id: "fb-rtdb-open", group: G_DB, source: "system", title: "Realtime Database cho phép bất kỳ ai đọc", severity: "critical", status: "fail", summary: `Không cần đăng nhập vẫn đọc được gốc database (${keys.length ? `${keys.length} nhánh dữ liệu` : "hiện đang trống"}). Chúng tôi chỉ xem tên nhánh, không tải dữ liệu.`, why: "Quy tắc đang là public (\".read\": true). Ai biết địa chỉ database đều tải được toàn bộ dữ liệu, và thường cả ghi đè.", fix: { summary: "Đổi Rules về chỉ cho người đã đăng nhập và theo từng người dùng.", steps: ["Vào Firebase Console → Realtime Database → Rules.", "Thay quy tắc public bằng quy tắc theo người dùng như ví dụ.", "Bấm Publish rồi quét lại."], snippet: { label: "Rules an toàn hơn", language: "json", code: "{\n  \"rules\": {\n    \"users\": {\n      \"$uid\": { \".read\": \"auth != null && auth.uid === $uid\", \".write\": \"auth != null && auth.uid === $uid\" }\n    }\n  }\n}" } }, evidence: [`GET https://${h}/.json?shallow=true → 200`, ...(keys.length ? [`Nhánh gốc: ${cap(keys, 5).join(", ")}`] : [])] }));
      rtdb = "open"; break;
    }
    if (r.status === 401) { rtdb = "closed"; break; }
  }
  if (rtdb === "closed") items.push(item({ id: "fb-rtdb-closed", group: G_DB, source: "system", title: "Realtime Database không đọc được công khai", severity: "info", status: "pass", summary: "Truy cập ẩn danh bị từ chối (Permission denied).", why: "Quy tắc bảo vệ đang hoạt động ở mức gốc." }));
  else if (rtdb === "none") items.push(item({ id: "fb-rtdb-none", group: G_DB, source: "system", title: "Không thấy Realtime Database", severity: "info", status: "info", summary: "Dự án không dùng Realtime Database hoặc địa chỉ khác mặc định. Nhập databaseURL ở mục \"Tuỳ chọn\" nếu có.", why: "Chỉ để biết phạm vi đã kiểm tra." }));

  // --- Firestore
  const base = `https://firestore.googleapis.com/v1/projects/${pid}/databases/(default)/documents`;
  const lc = await probe(f, `${base}:listCollectionIds`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  let fsOpen = false;
  if (lc?.status === 200) {
    const ids = ((lc.json as { collectionIds?: string[] } | null)?.collectionIds ?? []);
    fsOpen = true;
    items.push(item({ id: "fb-firestore-open", group: G_DB, source: "system", title: "Firestore cho phép bất kỳ ai xem các bộ sưu tập", severity: "critical", status: "fail", summary: `Không cần đăng nhập vẫn liệt kê được ${ids.length} collection. Chúng tôi chỉ xem tên, không đọc tài liệu.`, why: "Rules đang quá rộng (ví dụ allow read, write: if true). Người lạ có thể đọc và có thể cả ghi/xoá dữ liệu.", fix: { summary: "Viết lại Firestore Rules: mặc định từ chối, chỉ mở theo từng người dùng.", steps: ["Vào Firebase Console → Firestore Database → Rules.", "Xoá quy tắc \"if true\" và dùng mẫu bên dưới.", "Publish rồi quét lại."], snippet: { label: "Rules theo người dùng", language: "js", code: "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /users/{uid} {\n      allow read, write: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}" } }, evidence: ["POST :listCollectionIds → 200", ...(ids.length ? [`Collection: ${cap(ids, 6).join(", ")}`] : [])] }));
  }
  if (!fsOpen && lc && lc.status !== 404) {
    const col = await mapPool(["users", "profiles", "orders", "messages", "posts", "customers", "accounts"], 4, async (c) => {
      const r = await probe(f, `${base}/${c}?pageSize=1&mask.fieldPaths=__name__`);
      const docs = (r?.json as { documents?: unknown[] } | null)?.documents;
      return { c, open: r?.status === 200 && Array.isArray(docs) && docs.length > 0 };
    });
    const o = col.filter((x) => x.open);
    if (o.length) { fsOpen = true; items.push(item({ id: "fb-firestore-collection-open", group: G_DB, source: "system", title: `Firestore: ${o.length} collection đọc được công khai`, severity: "critical", status: "fail", summary: `Collection ${o.map((x) => `"${x.c}"`).join(", ")} có tài liệu mà người chưa đăng nhập vẫn đọc được (chúng tôi chỉ xem tên tài liệu).`, why: "Rules cho phép đọc không cần đăng nhập.", fix: { summary: "Giới hạn Rules cho các collection này theo người dùng đã đăng nhập.", snippet: { label: "Rules", language: "js", code: "match /users/{uid} {\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}" } }, evidence: o.map((x) => `GET /documents/${x.c} → 200`) })); }
  }
  if (!fsOpen && lc) items.push(lc.status === 404
    ? item({ id: "fb-firestore-none", group: G_DB, source: "system", title: "Không thấy Firestore", severity: "info", status: "info", summary: "Dự án chưa bật Firestore (hoặc dùng database khác tên).", why: "Chỉ để biết phạm vi đã kiểm tra." })
    : item({ id: "fb-firestore-closed", group: G_DB, source: "system", title: "Firestore không đọc được công khai", severity: "info", status: "pass", summary: "Truy cập ẩn danh bị từ chối ở mức gốc và ở các collection phổ biến đã thử.", why: "Rules đang chặn người lạ.", evidence: ["Chỉ thử một số tên collection phổ biến."] }));

  // --- Storage
  const buckets = bucketIn ? [bucketIn] : [`${pid}.firebasestorage.app`, `${pid}.appspot.com`];
  let st: "open" | "closed" | "none" = "none";
  for (const b of buckets) {
    const r = await probe(f, `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(b)}/o?maxResults=1&delimiter=%2F`);
    if (!r) continue;
    if (r.status === 200) {
      items.push(item({ id: "fb-storage-open", group: G_STORAGE, source: "system", title: "Cloud Storage cho phép bất kỳ ai liệt kê file", severity: "high", status: "fail", summary: "Người lạ xem được danh sách file trong bucket (chúng tôi chỉ xem 1 mục, không tải file).", why: "Khi tên file lộ, kẻ xấu tải hàng loạt: ảnh giấy tờ, tài liệu, bản sao lưu…", fix: { summary: "Sửa Storage Rules, mặc định từ chối và chỉ mở cho người đã đăng nhập.", snippet: { label: "Storage Rules", language: "js", code: "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /users/{uid}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}" } }, evidence: [`GET /v0/b/${b}/o → 200`] }));
      st = "open"; break;
    }
    if (r.status === 403 || r.status === 401) { st = "closed"; break; }
  }
  if (st === "closed") items.push(item({ id: "fb-storage-closed", group: G_STORAGE, source: "system", title: "Cloud Storage không liệt kê được công khai", severity: "info", status: "pass", summary: "Truy cập ẩn danh vào danh sách file bị từ chối.", why: "File không bị lộ qua danh sách." }));
  else if (st === "none") items.push(item({ id: "fb-storage-none", group: G_STORAGE, source: "system", title: "Không thấy Cloud Storage", severity: "info", status: "info", summary: "Không tìm thấy bucket mặc định. Nhập tên bucket ở mục \"Tuỳ chọn\" nếu có.", why: "Chỉ để biết phạm vi đã kiểm tra." }));

  // --- Auth / API key
  if (apiKey) {
    const r = await probe(f, `https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=${apiKey}`);
    const j = r?.json as { projectId?: string; authorizedDomains?: string[]; enableAnonymousUser?: boolean; error?: { message?: string; errors?: { reason?: string }[]; details?: { reason?: string }[] } } | null;
    if (r?.status === 200 && j) {
      if (j.projectId && j.projectId !== pid) items.push(item({ id: "fb-key-mismatch", group: G_KEY, source: "system", title: "API key thuộc dự án khác", severity: "info", status: "unknown", summary: "API key không khớp mã dự án bạn nhập, nên các kiểm tra Auth không đáng tin.", why: "Cần nhập đúng cặp." }));
      const domains = j.authorizedDomains ?? [];
      items.push(item({ id: "fb-key-unrestricted", group: G_KEY, source: "system", title: "API key chưa giới hạn theo website", severity: "low", status: "fail", confidence: "medium", summary: "Key gọi được từ máy chủ lạ không kèm website nào. Key Firebase vốn công khai, nhưng nên giới hạn để chặn lạm dụng hạn mức.", why: "Kẻ xấu có thể dùng key của bạn cho ứng dụng của họ và tiêu tốn hạn mức/chi phí.", fix: { summary: "Giới hạn key theo HTTP referrer và theo API.", steps: ["Vào Google Cloud Console → APIs & Services → Credentials.", "Mở API key → Application restrictions → HTTP referrers, thêm tên miền của bạn.", "API restrictions: chỉ chọn các API Firebase bạn dùng."] }, evidence: [] }));
      if (domains.includes("localhost")) items.push(item({ id: "fb-auth-localhost", group: G_AUTH, source: "system", title: "Đăng nhập cho phép domain \"localhost\"", severity: "low", status: "fail", confidence: "medium", summary: "Danh sách Authorized domains còn có localhost.", why: "Nếu ra mắt thật, ai chạy ứng dụng ở máy họ với key của bạn cũng đăng nhập được.", fix: { summary: "Xoá localhost khỏi Authorized domains khi ra mắt.", steps: ["Firebase Console → Authentication → Settings → Authorized domains → xoá localhost."] }, evidence: [`${domains.length} domain được phép`] }));
      else items.push(item({ id: "fb-auth-localhost", group: G_AUTH, source: "system", title: "Domain đăng nhập được phép đã gọn", severity: "info", status: "pass", summary: `${domains.length} domain được phép, không có localhost.`, why: "Giảm rủi ro dùng key ngoài ý muốn." }));
      if (j.enableAnonymousUser) items.push(item({ id: "fb-auth-anonymous", group: G_AUTH, source: "system", title: "Đăng nhập ẩn danh đang bật", severity: "low", status: "info", summary: "Bất kỳ ai cũng có thể lấy một tài khoản ẩn danh. Rules không nên coi \"đã đăng nhập\" là \"đáng tin\".", why: "Rules dạng request.auth != null sẽ cho cả người ẩn danh vào.", fix: { summary: "Tắt nếu không dùng, hoặc viết Rules kiểm tra thêm điều kiện." }, evidence: [] }));
    } else {
      const blob = JSON.stringify(j?.error ?? "") + (r?.body ?? "");
      if (/REFERRER|API_KEY_HTTP|IP_ADDRESS_BLOCKED|referer/i.test(blob)) items.push(item({ id: "fb-key-unrestricted", group: G_KEY, source: "system", title: "API key đã được giới hạn theo website", severity: "info", status: "pass", summary: "Yêu cầu không kèm website hợp lệ bị từ chối. Đây là cấu hình tốt.", why: "Chặn người khác dùng key của bạn." }));
      else items.push(item({ id: "fb-key-unknown", group: G_KEY, source: "system", title: "Chưa kiểm tra được API key", severity: "info", status: "unknown", summary: "Key bị từ chối hoặc dịch vụ không phản hồi. Hãy kiểm tra key còn hiệu lực.", why: "Cần để đánh giá cấu hình đăng nhập." }));
    }
  } else items.push(item({ id: "fb-auth-unknown", group: G_AUTH, source: "system", title: "Chưa kiểm tra cấu hình đăng nhập", severity: "info", status: "unknown", summary: "Dán API key Firebase (công khai, có trong code frontend) ở mục \"Tuỳ chọn\" để kiểm tra giới hạn key và domain đăng nhập.", why: "Key không giới hạn và domain thừa là lỗi thường gặp." }));

  items.push(item({ id: "fb-write-unchecked", group: G_DB, source: "system", title: "Quyền ghi và App Check chưa được kiểm tra", severity: "medium", status: "unknown", summary: "Chúng tôi không ghi dữ liệu và không đăng ký tài khoản thử nên không thể xác nhận quyền ghi của người lạ. Hãy thử trong Rules Playground của Firebase.", why: "Một collection chỉ cho đọc nhưng lỡ cho ghi vẫn bị phá hoại. Nên bật App Check để chặn ứng dụng giả.", fix: { summary: "Dùng Rules Playground và bật App Check.", steps: ["Firebase Console → Firestore/Storage → Rules → Rules Playground: thử thao tác ghi khi chưa đăng nhập, kết quả phải là Denied.", "Bật App Check cho Firestore, Storage và Realtime Database."] } }));
  return { label: pid, items };
}

const cap = <T>(a: T[], n: number) => a.slice(0, n);

async function mapPool<T, R>(arr: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(arr.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, arr.length) }, async () => { while (i < arr.length) { const k = i++; out[k] = await fn(arr[k]!); } }));
  return out;
}
export type { Severity };
