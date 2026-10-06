import { detectSecrets, redact, type SecretMatch } from "../scanner/secrets";
import type { Severity } from "../scanner/types";
import type { SourceFile } from "./github";
import { item, type ProjectItem } from "./types";

/**
 * Phân tích TĨNH mã nguồn (chỉ đọc chuỗi, không chạy mã). Mọi bằng chứng đều được che: bí mật chỉ hiện nhãn + độ dài,
 * tuyệt đối không có giá trị đầy đủ. Hàm thuần: không I/O, kết quả tất định.
 */

const G_SECRET = "Khoá bí mật & mật khẩu";
const G_FILES = "File nhạy cảm";
const G_CODE = "Cách viết code không an toàn";
const G_CONFIG = "Cấu hình dự án";

const TEST_PATH = /(?:^|\/)(?:__tests__|tests?|specs?|fixtures?|mocks?|__mocks__|examples?|samples?|docs?|e2e|cypress|storybook|locales?|i18n|translations?)(?:\/|$)|\.(?:test|spec|stories)\.[cm]?[jt]sx?$/i;
const MINIFIED = /\.min\.|[.-]bundle\.|(?:^|\/)(?:package-lock\.json|yarn\.lock)$/;
const PLACEHOLDER = /(example|placeholder|your[_-]?|xxxx|\*{3,}|<[^>]+>|changeme|dummy|sample|todo|replace|insert|password|secret|token|apikey|api_key|undefined|null|true|false|process\.env|import\.meta|env\.|\$\{|%s|\{\{)/i;

const lineOf = (text: string, index: number) => { let n = 1; for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++; return n; };
const where = (path: string, line?: number) => (line ? `${path}:${line}` : path);
const cap = <T>(a: T[], n: number) => a.slice(0, n);
const extra = (n: number, shown: number) => (n > shown ? [`… và ${n - shown} chỗ khác`] : []);
const isTest = (p: string) => TEST_PATH.test(p);

function entropy(s: string): number {
  const m = new Map<string, number>();
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

// ------------------------------------------------------------------ 1. khoá bí mật

const SECRET_FIX = (what: string) => ({
  summary: `Thu hồi (đổi) ${what} ngay, rồi chuyển giá trị mới sang biến môi trường.`,
  steps: [
    "Vào trang quản lý của dịch vụ đó và TẠO KHOÁ MỚI, sau đó xoá/thu hồi khoá cũ. Chỉ xoá khỏi code là chưa đủ vì khoá vẫn còn trong lịch sử Git.",
    "Đặt khoá mới trong file .env (đã được .gitignore chặn) hoặc phần Environment Variables của nơi bạn triển khai (Vercel, Cloudflare…).",
    "Trong code chỉ đọc qua process.env.TEN_BIEN, không viết giá trị trực tiếp.",
    "Nếu kho là công khai, hãy coi khoá cũ đã bị lộ và kiểm tra lịch sử sử dụng của nó.",
  ],
  snippet: { label: "Đọc khoá từ biến môi trường", language: "ts", code: "const key = process.env.SERVICE_API_KEY;\nif (!key) throw new Error(\"Thiếu SERVICE_API_KEY\");" },
});

function findSecrets(files: SourceFile[]): ProjectItem[] {
  const byRule = new Map<string, { m: SecretMatch; where: string[] }>();
  for (const f of files) {
    if (MINIFIED.test(f.path) || /\.md$/i.test(f.path) && f.content.length > 200_000) continue;
    const hits = detectSecrets(f.content);
    if (hits.length === 0) continue;
    // Xác định số dòng: quét từng dòng chỉ khi file đã có kết quả (rẻ).
    const lines = f.content.split("\n");
    for (const h of hits) {
      let line: number | undefined;
      for (let i = 0; i < lines.length && line === undefined; i++) {
        const l = lines[i]!;
        if (l.length > 4000) continue;
        if (detectSecrets(l).some((x) => x.id === h.id && x.redacted === h.redacted)) line = i + 1;
      }
      const e = byRule.get(h.id) ?? { m: h, where: [] };
      e.where.push(`${where(f.path, line)} — ${h.redacted}${isTest(f.path) ? " (trong file test/ví dụ)" : ""}`);
      byRule.set(h.id, e);
    }
  }
  const out: ProjectItem[] = [];
  for (const [id, { m, where: w }] of byRule) {
    if (m.publicByDesign) {
      out.push(item({
        id: `secret-${id}`, group: G_SECRET, source: "code", title: `${m.label} trong mã nguồn`, severity: "info", status: "info",
        summary: `Tìm thấy ${w.length} ${m.label.toLowerCase()}. ${m.note}`, why: "Loại khoá này được thiết kế để nằm trong ứng dụng chạy ở trình duyệt, nên không phải lỗi, nhưng an toàn của bạn phụ thuộc vào cách cấu hình phía dịch vụ.",
        evidence: [...cap(w, 5), ...extra(w.length, 5)], fingerprint: `secret-${id}`,
      }));
      continue;
    }
    out.push(item({
      id: `secret-${id}`, group: G_SECRET, source: "code", title: `Lộ ${m.label}`, severity: m.severity, confidence: m.confidence, status: "fail",
      summary: `Có ${w.length} chỗ trong mã nguồn chứa ${m.label.toLowerCase()} viết thẳng vào file. ${m.note}`,
      why: "Ai xem được kho mã (hoặc lịch sử Git) đều dùng được khoá này như chính bạn: đọc dữ liệu, gửi email, tiêu tiền hoặc chiếm quyền dịch vụ.",
      fix: SECRET_FIX(m.label.toLowerCase()), evidence: [...cap(w, 8), ...extra(w.length, 8)],
      technical: `Phát hiện bởi mẫu "${id}". Giá trị đã được che, chỉ hiện ký tự đầu và độ dài.`, fingerprint: `secret-${id}:${w[0]!.split(" — ")[0]}`,
    }));
  }
  const failed = out.some((o) => o.status === "fail");
  if (!failed) out.push(item({ id: "secrets-clean", group: G_SECRET, source: "code", title: "Không thấy khoá bí mật viết thẳng trong code", severity: "info", status: "pass", summary: "Không tìm thấy khoá API, token hay chuỗi kết nối có mật khẩu thuộc các dịch vụ phổ biến.", why: "Khoá nằm trong code là nguyên nhân phổ biến nhất khiến dự án bị lộ dữ liệu." }));
  return out;
}

/** Mật khẩu / khoá viết cứng kiểu `password: "abc12345"` (phát hiện theo tên biến, lọc giá trị giả). */
function findHardcoded(files: SourceFile[]): ProjectItem[] {
  const re = /((?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\w*)["']?\s*[:=]\s*["']([^"'\s$`{}<>]{8,64})["']/gi;
  const hits: string[] = [];
  for (const f of files) {
    if (isTest(f.path) || MINIFIED.test(f.path) || /\.(?:md|lock|txt|json)$/i.test(f.path) && !/(?:^|\/)(?:config|settings|credentials)[\w.-]*\.json$/i.test(f.path)) continue;
    if (/(?:^|\/)\.env\.(?:example|sample|template|dist|defaults)$/i.test(f.path)) continue;
    re.lastIndex = 0;
    for (const m of f.content.matchAll(re)) {
      const v = m[2]!;
      if (PLACEHOLDER.test(v) || entropy(v) < 2.8) continue;
      if (!(/[a-z]/.test(v) && (/[A-Z]/.test(v) || /\d/.test(v) || /[^\w]/.test(v)))) continue;
      hits.push(`${where(f.path, lineOf(f.content, m.index ?? 0))} — biến "${m[1]}" = giá trị ${redact(v).replace(/^[^…]*/, "•••")}`);
      if (hits.length >= 40) break;
    }
  }
  if (hits.length === 0) return [item({ id: "hardcoded-clean", group: G_SECRET, source: "code", title: "Không thấy mật khẩu viết cứng trong code", severity: "info", status: "pass", summary: "Không tìm thấy dòng nào gán mật khẩu/khoá cho biến kiểu password = \"…\".", why: "Mật khẩu viết cứng ai đọc code cũng thấy." })];
  return [item({
    id: "hardcoded-credentials", group: G_SECRET, source: "code", title: "Có mật khẩu hoặc khoá viết thẳng trong code", severity: "high", confidence: "medium", status: "fail",
    summary: `Có ${hits.length} dòng gán giá trị trông giống mật khẩu/khoá trực tiếp trong code (giá trị đã được ẩn).`,
    why: "Mật khẩu nằm trong code sẽ đi theo mọi bản sao của kho, kể cả lịch sử Git. Người xem code có thể đăng nhập bằng nó.",
    fix: SECRET_FIX("mật khẩu/khoá này"), evidence: [...cap(hits, 8), ...extra(hits.length, 8)], technical: "Phát hiện theo tên biến nhạy cảm + giá trị có độ ngẫu nhiên cao; đã loại giá trị mẫu, biến môi trường và file test. Có thể có dương tính giả.",
    fingerprint: `hardcoded:${hits[0]!.split(" — ")[0]}`,
  })];
}

// ------------------------------------------------------------------ 2. file nhạy cảm

interface SensitiveRule { id: string; re: RegExp; title: string; severity: Severity; why: string; needsContent?: (c: string) => boolean }
const SENSITIVE: SensitiveRule[] = [
  { id: "private-key-file", re: /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:pem|key|p12|pfx|jks|keystore))$/i, title: "File khoá riêng tư được đưa lên kho", severity: "critical", why: "Khoá riêng tư cho phép giả mạo máy chủ của bạn hoặc giải mã dữ liệu.", needsContent: (c) => /PRIVATE KEY-----/.test(c) || c.length === 0 },
  { id: "service-account-file", re: /(?:^|\/)(?:[^/]*firebase-adminsdk[^/]*|serviceAccount[^/]*|service-account[^/]*|credentials)\.json$/i, title: "File tài khoản dịch vụ (service account) trên kho", severity: "critical", why: "File này cấp toàn quyền quản trị cho dự án đám mây của bạn.", needsContent: (c) => /"private_key"|"client_secret"/.test(c) },
  { id: "netrc-file", re: /(?:^|\/)(?:\.git-credentials|\.htpasswd|\.pypirc|terraform\.tfstate(?:\.backup)?|[^/]+\.tfvars)$/i, title: "File chứa thông tin đăng nhập hoặc trạng thái hạ tầng", severity: "high", why: "Các file này thường chứa mật khẩu hoặc khoá thật." },
  { id: "npmrc-token", re: /(?:^|\/)\.npmrc$/, title: "File .npmrc chứa token đăng nhập npm", severity: "critical", why: "Token npm cho phép đăng gói phần mềm dưới tên bạn.", needsContent: (c) => /_authToken\s*=\s*(?!\$\{)\S{10,}/.test(c) },
  { id: "database-file", re: /(?:^|\/)[^/]+\.(?:sqlite3?|db|mdb)$/i, title: "File cơ sở dữ liệu nằm trên kho", severity: "high", why: "File database có thể chứa dữ liệu người dùng thật." },
  { id: "dump-file", re: /(?:^|\/)[^/]*(?:dump|backup)[^/]*\.(?:sql|gz|zip|tar)$/i, title: "File sao lưu/dump dữ liệu nằm trên kho", severity: "high", why: "Bản sao lưu thường chứa toàn bộ dữ liệu người dùng." },
  { id: "wp-config", re: /(?:^|\/)wp-config\.php$/i, title: "File cấu hình WordPress (wp-config.php) trên kho", severity: "high", why: "File này chứa mật khẩu database và khoá bảo mật của WordPress.", needsContent: (c) => /DB_PASSWORD['"]\s*,\s*['"][^'"]+/.test(c) },
];
const ENV_FILE = /(?:^|\/)\.env(?:\.[\w.-]+)?$/i;
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults)$/i;
const SENSITIVE_KEY = /(SECRET|KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|DATABASE_URL|DB_URL|SERVICE_ROLE|DSN|CONNECTION)/i;

function findSensitiveFiles(files: SourceFile[], allPaths: string[]): ProjectItem[] {
  const byPath = new Map(files.map((f) => [f.path, f.content]));
  const out: ProjectItem[] = [];

  const envHits: { path: string; names: string[]; secretNames: string[] }[] = [];
  for (const p of allPaths) {
    if (!ENV_FILE.test(p) || ENV_TEMPLATE.test(p) || isTest(p)) continue;
    const c = byPath.get(p) ?? "";
    const names: string[] = [];
    for (const m of c.matchAll(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/gm)) {
      const v = m[2]!.trim().replace(/^["']|["']$/g, "");
      if (v && !PLACEHOLDER.test(v)) names.push(m[1]!);
    }
    envHits.push({ path: p, names, secretNames: names.filter((n) => SENSITIVE_KEY.test(n)) });
  }
  const real = envHits.filter((e) => e.names.length > 0);
  if (real.length) {
    const hasSecret = real.some((e) => e.secretNames.length > 0);
    out.push(item({
      id: "env-file-committed", group: G_FILES, source: "code", title: "File .env (chứa cấu hình thật) đã được đưa lên kho", severity: hasSecret ? "critical" : "high", status: "fail",
      summary: `Có ${real.length} file .env có giá trị thật nằm trong kho${hasSecret ? ", trong đó có biến trông như khoá/mật khẩu" : ""}. Giá trị không được hiển thị.`,
      why: "File .env là nơi chứa mật khẩu, khoá API, chuỗi kết nối database. Đưa nó lên Git nghĩa là bất kỳ ai đọc được kho đều có chúng.",
      fix: {
        summary: "Gỡ file .env khỏi Git, chặn nó bằng .gitignore và đổi mọi khoá trong đó.",
        steps: ["Chạy lệnh bên dưới để Git ngừng theo dõi file (file vẫn còn trên máy bạn).", "Thêm .env* vào .gitignore (chừa lại .env.example làm mẫu).", "ĐỔI toàn bộ khoá/mật khẩu trong file đó vì chúng đã nằm trong lịch sử Git.", "Nếu kho công khai, cân nhắc dùng git filter-repo hoặc BFG để xoá khỏi lịch sử."],
        snippet: { label: "Ngừng theo dõi .env", language: "bash", code: "git rm --cached .env .env.local .env.production\necho \".env*\\n!.env.example\" >> .gitignore\ngit commit -m \"Stop tracking env files\"" },
      },
      evidence: cap(real.map((e) => `${e.path} — ${e.names.length} biến có giá trị: ${cap(e.secretNames.length ? e.secretNames : e.names, 6).join(", ")}`), 6),
      fingerprint: `env-file-committed:${real[0]!.path}`,
    }));
  }
  for (const r of SENSITIVE) {
    const hits = allPaths.filter((p) => r.re.test(p) && !isTest(p) && (!r.needsContent || r.needsContent(byPath.get(p) ?? "")));
    if (hits.length === 0) continue;
    out.push(item({
      id: r.id, group: G_FILES, source: "code", title: r.title, severity: r.severity, status: "fail",
      summary: `Tìm thấy ${hits.length} file: ${cap(hits, 3).join(", ")}${hits.length > 3 ? "…" : ""}. Nội dung không được hiển thị.`, why: r.why,
      fix: { summary: "Gỡ file khỏi Git, thêm vào .gitignore và đổi các khoá liên quan.", steps: ["Chạy git rm --cached <đường dẫn> để Git ngừng theo dõi file.", "Thêm đường dẫn đó vào .gitignore.", "Tạo lại khoá/mật khẩu liên quan vì bản cũ đã nằm trong lịch sử Git."] },
      evidence: cap(hits, 8), fingerprint: `${r.id}:${hits[0]}`,
    }));
  }
  if (!out.length) out.push(item({ id: "sensitive-files-clean", group: G_FILES, source: "code", title: "Không có file nhạy cảm trên kho", severity: "info", status: "pass", summary: "Không thấy file .env thật, khoá riêng tư, tài khoản dịch vụ hay file database được đưa lên kho.", why: "Những file này thường chứa chìa khoá vào toàn bộ hệ thống." }));
  return out;
}

// ------------------------------------------------------------------ 3. mẫu code không an toàn

interface CodeRule {
  id: string; title: string; severity: Severity; confidence: "high" | "medium" | "low";
  exts: RegExp; re: RegExp; requires?: RegExp; skipPath?: RegExp;
  summary: string; why: string; fix: NonNullable<ProjectItem["fix"]>; technical: string;
}
const JS = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/i;
const CODE_RULES: CodeRule[] = [
  { id: "code-eval", title: "Chạy chuỗi như mã lệnh (eval)", severity: "medium", confidence: "medium", exts: /\.(?:[cm]?[jt]sx?|py|php|rb)$/i, re: /(?<![\w.$])eval\s*\(|new\s+Function\s*\(/g,
    summary: "Code dùng eval() hoặc new Function() để biến một chuỗi thành lệnh chạy.", why: "Nếu chuỗi đó có chữ do người dùng nhập, kẻ xấu có thể chạy lệnh tuỳ ý trong ứng dụng của bạn.",
    fix: { summary: "Thay eval bằng cách xử lý dữ liệu an toàn (JSON.parse, bảng tra cứu, hàm có sẵn).", steps: ["Nếu chỉ cần đọc dữ liệu: dùng JSON.parse thay vì eval.", "Nếu cần chọn hành vi theo chuỗi: dùng object/map ánh xạ tên → hàm.", "Không bao giờ đưa dữ liệu người dùng vào eval hay new Function."] }, technical: "CWE-95 (Eval Injection)." },
  { id: "code-html-injection", title: "Chèn HTML trực tiếp vào trang (nguy cơ XSS)", severity: "medium", confidence: "medium", exts: JS, re: /\.(?:innerHTML|outerHTML)\s*=(?!=)|dangerouslySetInnerHTML|document\.write\s*\(|v-html\s*=/g,
    summary: "Code chèn nội dung HTML thô vào trang (innerHTML, dangerouslySetInnerHTML, v-html…).", why: "Nếu nội dung đó có phần do người dùng nhập, kẻ xấu có thể cài script chạy trên trình duyệt của người khác (XSS) và đánh cắp phiên đăng nhập.",
    fix: { summary: "Dùng textContent / JSX thông thường; nếu buộc phải chèn HTML, lọc bằng DOMPurify.", steps: ["Đổi el.innerHTML = x thành el.textContent = x khi chỉ cần hiển thị chữ.", "Với React, hiển thị {value} thay vì dangerouslySetInnerHTML.", "Nếu cần HTML thật (bài viết, markdown): lọc qua DOMPurify.sanitize() trước khi chèn."], snippet: { label: "Lọc HTML bằng DOMPurify", language: "ts", code: "import DOMPurify from \"dompurify\";\nel.innerHTML = DOMPurify.sanitize(html);" } }, technical: "CWE-79 (Cross-site Scripting)." },
  { id: "code-sql-concat", title: "Ghép chuỗi vào câu lệnh SQL (nguy cơ SQL injection)", severity: "high", confidence: "medium", exts: /\.(?:[cm]?[jt]sx?|py|php|rb|java|kt|cs|go)$/i,
    re: /\b(?:query|execute|exec|raw|queryRawUnsafe|executeRawUnsafe)\s*\(\s*(?:`[^`\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`\n]*\$\{|["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*(?:\+|%\s*\w|\.format\())/gi,
    summary: "Câu lệnh SQL được ghép từ chuỗi có chèn biến thẳng vào.", why: "Nếu biến đó đến từ người dùng, kẻ xấu có thể thêm lệnh SQL của họ để đọc, sửa hoặc xoá toàn bộ database.",
    fix: { summary: "Dùng câu lệnh có tham số (placeholder $1, ?) thay vì ghép chuỗi.", steps: ["Viết SQL với chỗ trống ($1, ? hoặc :name) và truyền giá trị riêng ở tham số thứ hai.", "Hoặc dùng ORM/query builder (Prisma, Drizzle, Supabase client) thay vì SQL thủ công."], snippet: { label: "Truy vấn có tham số", language: "ts", code: "// Thay vì: db.query(`SELECT * FROM users WHERE id = ${id}`)\nawait db.query(\"SELECT * FROM users WHERE id = $1\", [id]);" } }, technical: "CWE-89 (SQL Injection). Phát hiện theo mẫu, cần xem lại ngữ cảnh." },
  { id: "code-shell-injection", title: "Chạy lệnh hệ thống có chèn dữ liệu biến đổi", severity: "high", confidence: "medium", exts: /\.(?:[cm]?[jt]sx?|py)$/i,
    re: /\b(?:exec|execSync)\s*\(\s*(?:`[^`\n]*\$\{|[^)\n,]*["']\s*\+\s*\w)|os\.system\s*\(\s*(?:f["']|[^)\n]*(?:\+|%\s*\w|\.format\())|shell\s*=\s*True/g, requires: /child_process|os\.system|subprocess/,
    summary: "Code chạy lệnh hệ thống (shell) với chuỗi được ghép từ biến.", why: "Nếu biến chứa dữ liệu người dùng, kẻ xấu có thể chèn lệnh riêng và điều khiển máy chủ của bạn.",
    fix: { summary: "Dùng execFile/spawn với mảng tham số, không ghép chuỗi vào lệnh shell.", steps: ["Thay exec(`cmd ${x}`) bằng execFile(\"cmd\", [x]).", "Trong Python: subprocess.run([\"cmd\", x]) và bỏ shell=True.", "Kiểm tra/giới hạn giá trị x theo danh sách cho phép."] }, technical: "CWE-78 (OS Command Injection)." },
  { id: "code-tls-off", title: "Tắt kiểm tra chứng chỉ HTTPS", severity: "high", confidence: "high", exts: /\.(?:[cm]?[jt]sx?|py|go|java|kt|cs|rb|php|env|sh)$/i, skipPath: /(?:^|\/)\.env\./,
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/g,
    summary: "Code bỏ qua việc kiểm tra chứng chỉ HTTPS khi gọi dịch vụ khác.", why: "Kết nối trông như được mã hoá nhưng kẻ xen giữa vẫn có thể đọc và sửa dữ liệu mà không bị phát hiện.",
    fix: { summary: "Bật lại kiểm tra chứng chỉ; nếu đang dùng chứng chỉ tự ký khi phát triển, chỉ tắt ở môi trường dev.", steps: ["Xoá rejectUnauthorized: false / verify=False.", "Nếu lỗi xuất hiện, cài chứng chỉ gốc đúng hoặc dùng chứng chỉ hợp lệ (Let's Encrypt miễn phí)."] }, technical: "CWE-295 (Improper Certificate Validation)." },
  { id: "code-cors-open", title: "Cho phép mọi website gọi API (CORS mở)", severity: "medium", confidence: "medium", exts: /\.(?:[cm]?[jt]sx?|py|go|java|kt|cs|rb|php)$/i,
    re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|cors\(\s*\{[^}]*origin\s*:\s*(?:true|['"]\*['"])|allow_origins\s*=\s*\[\s*['"]\*['"]/g,
    summary: "API được cấu hình cho phép mọi website khác gọi vào (origin = *).", why: "Nếu API trả dữ liệu theo đăng nhập, website lạ có thể đọc dữ liệu đó thay mặt người dùng đang đăng nhập.",
    fix: { summary: "Chỉ cho phép đúng tên miền của bạn.", steps: ["Liệt kê các website được phép gọi API (ví dụ https://app.congty.com).", "Đặt origin là danh sách đó thay vì \"*\" hoặc true."], snippet: { label: "CORS có danh sách cho phép", language: "ts", code: "app.use(cors({ origin: [\"https://app.example.com\"], credentials: true }));" } }, technical: "CWE-942 (Permissive Cross-domain Policy)." },
  { id: "code-jwt-weak", title: "Kiểm tra token đăng nhập (JWT) lỏng lẻo", severity: "high", confidence: "high", exts: /\.(?:[cm]?[jt]sx?|py|php|rb|go|java)$/i,
    re: /algorithms?\s*:\s*\[?\s*['"]none['"]|ignoreExpiration\s*:\s*true|verify_signature['"]?\s*:\s*False|jwt\.decode\([^)\n]*verify\s*=\s*False/gi,
    summary: "Code chấp nhận token không ký hoặc bỏ qua hạn dùng của token.", why: "Kẻ xấu có thể tự tạo token giả để đăng nhập thành bất kỳ người dùng nào, hoặc dùng lại token đã hết hạn.",
    fix: { summary: "Luôn xác minh chữ ký và hạn dùng, chỉ chấp nhận thuật toán bạn chọn.", steps: ["Xoá ignoreExpiration: true và algorithms: ['none'].", "Chỉ định rõ thuật toán, ví dụ algorithms: ['HS256'], và dùng khoá bí mật mạnh."] }, technical: "CWE-347 (Improper Verification of Cryptographic Signature)." },
  { id: "code-weak-hash", title: "Dùng MD5/SHA-1 để băm mật khẩu", severity: "medium", confidence: "medium", exts: /\.(?:[cm]?[jt]sx?|py|php|rb)$/i, requires: /passw/i,
    re: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\(|\bmd5\s*\(\s*\$/g,
    summary: "File xử lý mật khẩu có dùng MD5 hoặc SHA-1.", why: "Hai thuật toán này quá nhanh và đã bị phá; nếu database bị lộ, mật khẩu bị dò ra rất nhanh.",
    fix: { summary: "Dùng bcrypt, scrypt hoặc argon2 cho mật khẩu.", steps: ["Cài thư viện bcrypt hoặc argon2.", "Băm mật khẩu bằng thư viện đó khi đăng ký và so sánh bằng hàm verify khi đăng nhập."] }, technical: "CWE-327/916 (Weak hash for passwords)." },
  { id: "code-weak-random", title: "Dùng số ngẫu nhiên yếu cho token/mã bí mật", severity: "low", confidence: "medium", exts: JS,
    re: /(?:token|secret|password|session|otp|apikey)\w*[^\n]{0,40}Math\.random\(\)|Math\.random\(\)[^\n]{0,40}(?:token|secret|password|session|otp)/gi,
    summary: "Mã/token được tạo bằng Math.random().", why: "Math.random() có thể đoán được, nên mã đặt lại mật khẩu hoặc token tạo bằng nó có thể bị dò.",
    fix: { summary: "Dùng bộ sinh số ngẫu nhiên an toàn: crypto.randomUUID() hoặc crypto.getRandomValues().", snippet: { label: "Token ngẫu nhiên an toàn", language: "ts", code: "const token = crypto.randomUUID();" } }, technical: "CWE-338 (Weak PRNG)." },
  { id: "code-public-secret-env", title: "Khoá bí mật bị đặt vào biến công khai (NEXT_PUBLIC_/VITE_…)", severity: "high", confidence: "high", exts: /\.(?:[cm]?[jt]sx?|vue|svelte|ya?ml|toml|html?)$/i,
    re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_\w*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)\w*/g,
    summary: "Có biến môi trường mang tên bí mật nhưng lại có tiền tố công khai, nghĩa là giá trị sẽ bị nhúng vào mã gửi cho mọi người truy cập.", why: "Mọi biến NEXT_PUBLIC_/VITE_… đều hiện ra trong trình duyệt. Đặt khoá bí mật ở đó là công bố nó cho cả thế giới.",
    fix: { summary: "Bỏ tiền tố công khai và chỉ đọc biến này ở phía máy chủ.", steps: ["Đổi tên biến (bỏ NEXT_PUBLIC_/VITE_…) và chỉ dùng trong API route/server action.", "Đổi khoá đó vì nó có thể đã lộ.", "Phía trình duyệt chỉ dùng khoá công khai (anon/publishable)."] }, technical: "Biến tiền tố công khai được nhúng vào bundle khi build." },
  { id: "code-debug-on", title: "Chế độ debug đang bật trong code", severity: "medium", confidence: "medium", exts: /\.py$/i,
    re: /app\.run\([^)\n]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/gm,
    summary: "Ứng dụng Flask/Django được đặt debug=True.", why: "Chế độ debug hiển thị mã nguồn, biến môi trường và có thể cho chạy lệnh từ trình duyệt khi có lỗi.",
    fix: { summary: "Chỉ bật debug khi phát triển; đọc từ biến môi trường.", snippet: { label: "Debug theo môi trường", language: "py", code: "DEBUG = os.environ.get(\"DEBUG\") == \"1\"" } }, technical: "CWE-489 (Active Debug Code)." },
  { id: "code-unsafe-deserialize", title: "Đọc dữ liệu bằng cách không an toàn (pickle/yaml.load)", severity: "medium", confidence: "medium", exts: /\.(?:py|php)$/i,
    re: /pickle\.loads?\(|yaml\.load\((?![^)\n]*Loader)|unserialize\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/g,
    summary: "Code đọc dữ liệu bằng hàm có thể chạy mã tuỳ ý nếu dữ liệu bị thay đổi.", why: "Nếu dữ liệu đến từ người dùng hoặc nguồn ngoài, kẻ xấu có thể chạy lệnh trên máy chủ của bạn.",
    fix: { summary: "Dùng định dạng an toàn: json.loads, yaml.safe_load, json_decode.", steps: ["Python: thay yaml.load bằng yaml.safe_load; thay pickle bằng JSON.", "PHP: dùng json_decode thay vì unserialize cho dữ liệu từ người dùng."] }, technical: "CWE-502 (Deserialization of Untrusted Data)." },
];

function findCodePatterns(files: SourceFile[]): ProjectItem[] {
  const out: ProjectItem[] = [];
  const candidates = files.filter((f) => !isTest(f.path) && !MINIFIED.test(f.path) && !/\.(?:md|json|lock|txt)$/i.test(f.path));
  for (const r of CODE_RULES) {
    const relevant = files.filter((f) => r.exts.test(f.path));
    if (relevant.length === 0) continue;
    const hits: string[] = [];
    let total = 0;
    for (const f of candidates) {
      if (!r.exts.test(f.path) || r.skipPath?.test(f.path) || (r.requires && !r.requires.test(f.content))) continue;
      r.re.lastIndex = 0;
      let perFile = 0;
      for (const m of f.content.matchAll(r.re)) {
        total++;
        if (hits.length < 8 && perFile++ < 3) hits.push(`${where(f.path, lineOf(f.content, m.index ?? 0))} — ${m[0].replace(/\s+/g, " ").slice(0, 70)}`);
      }
    }
    if (total === 0) { out.push(item({ id: r.id, group: G_CODE, source: "code", title: `Không thấy: ${r.title.charAt(0).toLowerCase()}${r.title.slice(1)}`, severity: "info", status: "pass", summary: "Không phát hiện mẫu code này.", why: r.why })); continue; }
    out.push(item({ id: r.id, group: G_CODE, source: "code", title: r.title, severity: r.severity, confidence: r.confidence, status: "fail", summary: `${r.summary} (${total} chỗ)`, why: r.why, fix: r.fix, evidence: [...hits, ...extra(total, hits.length)], technical: r.technical, fingerprint: `${r.id}:${hits[0]!.split(" — ")[0]!.split(":")[0]}` }));
  }

  // Khoá service_role dùng trong component chạy ở trình duyệt.
  const clientLeak = files.filter((f) => !isTest(f.path) && /^\s*['"]use client['"]/.test(f.content) && /SERVICE_ROLE|service_role/i.test(f.content));
  if (clientLeak.length) out.push(item({
    id: "code-service-role-client", group: G_CODE, source: "code", title: "Khoá service_role của Supabase được dùng trong code chạy ở trình duyệt", severity: "critical", status: "fail",
    summary: `${clientLeak.length} file "use client" nhắc tới service_role. Khoá này bỏ qua toàn bộ quy tắc bảo mật của database.`, why: "Code chạy ở trình duyệt sẽ được gửi cho mọi khách truy cập. Ai cũng có thể lấy khoá và đọc/xoá toàn bộ dữ liệu.",
    fix: { summary: "Chỉ dùng service_role trong API route/server action, và đổi khoá nếu đã từng lộ.", steps: ["Chuyển đoạn code đó sang phía máy chủ (route handler, server action, Edge Function).", "Phía trình duyệt chỉ dùng khoá anon cùng Row Level Security.", "Vào Supabase → Project Settings → API và tạo lại khoá service_role."] },
    evidence: cap(clientLeak.map((f) => f.path), 6), fingerprint: `code-service-role-client:${clientLeak[0]!.path}`,
  }));
  return out;
}

// ------------------------------------------------------------------ 4. cấu hình dự án

function findConfig(files: SourceFile[], allPaths: string[]): ProjectItem[] {
  const out: ProjectItem[] = [];
  const gi = files.find((f) => f.path === ".gitignore");
  const isApp = allPaths.some((p) => /(?:^|\/)(?:package\.json|requirements\.txt|pyproject\.toml|composer\.json|Gemfile)$/.test(p));
  if (isApp) {
    const ok = !!gi && /^\s*\/?\.env(?:\*|\.local|\b)/m.test(gi.content);
    out.push(ok
      ? item({ id: "gitignore-env", group: G_CONFIG, source: "code", title: ".gitignore đã chặn file .env", severity: "info", status: "pass", summary: "File .env được chặn khỏi Git.", why: "Giúp tránh vô tình đẩy khoá thật lên kho." })
      : item({ id: "gitignore-env", group: G_CONFIG, source: "code", title: ".gitignore chưa chặn file .env", severity: "low", status: "fail", summary: gi ? "File .gitignore có nhưng không chứa .env." : "Kho chưa có file .gitignore.", why: "Khi bạn tạo .env lần sau, một lệnh git add . có thể đẩy toàn bộ khoá thật lên kho mà không ai để ý.",
        fix: { summary: "Thêm .env vào .gitignore ngay từ bây giờ.", snippet: { label: ".gitignore", language: "bash", code: ".env\n.env.*\n!.env.example" } }, evidence: [] }));
  }
  const hasDockerfile = allPaths.find((p) => /(?:^|\/)Dockerfile$/.test(p));
  const df = hasDockerfile ? files.find((f) => f.path === hasDockerfile) : undefined;
  if (df) {
    const root = !/^\s*USER\s+(?!root\b)\S+/m.test(df.content);
    const secrets = [...df.content.matchAll(/^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY)[A-Z0-9_]*)[=\s]+(?!\$)(\S{6,})/gim)].map((m) => m[1]!);
    if (secrets.length) out.push(item({ id: "dockerfile-secrets", group: G_CONFIG, source: "code", title: "Dockerfile chứa khoá/mật khẩu viết cứng", severity: "high", status: "fail", summary: `ENV/ARG ${cap(secrets, 4).join(", ")} có giá trị cố định trong Dockerfile (giá trị đã ẩn).`, why: "Giá trị trong Dockerfile nằm lại trong mọi image và ai kéo image về cũng đọc được.", fix: { summary: "Truyền khoá lúc chạy (docker run -e / secrets) thay vì ghi trong Dockerfile." }, evidence: [df.path], fingerprint: `dockerfile-secrets:${df.path}` }));
    out.push(root
      ? item({ id: "dockerfile-root", group: G_CONFIG, source: "code", title: "Container chạy bằng quyền root", severity: "low", status: "fail", summary: "Dockerfile không đặt USER khác root.", why: "Nếu ứng dụng bị khai thác, kẻ xấu có toàn quyền trong container.", fix: { summary: "Thêm một USER không phải root vào Dockerfile.", snippet: { label: "Dockerfile", language: "dockerfile", code: "RUN addgroup -S app && adduser -S app -G app\nUSER app" } }, evidence: [df.path] })
      : item({ id: "dockerfile-root", group: G_CONFIG, source: "code", title: "Container không chạy bằng quyền root", severity: "info", status: "pass", summary: "Dockerfile đã đặt USER riêng.", why: "Giảm thiệt hại nếu ứng dụng bị khai thác." }));
  }
  return out;
}

export interface AnalyzeInput { files: SourceFile[]; allPaths: string[] }

/** Phân tích tĩnh (không gồm thư viện/CVE — xem deps.ts). */
export function analyzeSource({ files, allPaths }: AnalyzeInput): ProjectItem[] {
  return [...findSecrets(files), ...findHardcoded(files), ...findSensitiveFiles(files, allPaths), ...findCodePatterns(files), ...findConfig(files, allPaths)];
}
