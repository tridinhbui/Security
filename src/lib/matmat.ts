import { buildAllPrompt, buildFixPrompt } from "./ai-prompt";
import { GLOSSARY, PLAIN_TITLES } from "./beginner";
import { FEYNMAN, PLAIN_SEV, plainScore } from "./feynman";
import { explain, ROLE_LABEL } from "./scanner/explain";
import { IMPACT, urgencyFor, URGENCY_LABEL } from "./scanner/impact";
import { reproFor } from "./scanner/analyst";
import type { Finding } from "./scanner/types";

/**
 * Mật Mật — trợ lý dễ thương của VibeSec. KHÔNG dùng AI: nhận diện ý định bằng từ khoá và trả lời bằng nội dung viết sẵn
 * (giải thích Feynman + prompt ghép từ kết quả quét). Thuần hàm nên kiểm thử được.
 */
/** Mục (và tuỳ chọn một dòng bằng chứng) người dùng đang hỏi: chatbot tự hiểu ngữ cảnh, không cần giải thích lại. */
export interface Focus { finding: Finding; host: string; line?: string }
export interface BotContext { host: string; score: number; grade: string; platforms: string[]; issues: Finding[] }
export interface BotReply { text: string; chips: string[]; copy?: { label: string; text: string }; handoff?: boolean }

export const GREETING = "Chào bạn, mình là Mật Mật 🐾 Mình giúp bạn hiểu báo cáo bảo mật mà không cần biết kỹ thuật nhé. Bạn muốn hỏi gì?";

const strip = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/đ/g, "d");
const has = (q: string, ...words: string[]) => words.some((w) => q.includes(strip(w)));
const STOP = new Set(["la", "gi", "co", "khong", "cua", "toi", "minh", "bi", "nay", "sao", "the", "nao", "cho", "voi", "va", "nhu", "duoc", "hay", "mot", "cac", "trang", "website", "sua", "prompt", "code", "chong", "khac", "phuc", "cach", "nen"]);
const words = (s: string) => strip(s).split(/[^a-z0-9]+/).filter((w) => w.length > 2 && !STOP.has(w));

export function chipsFor(ctx: BotContext | null): string[] {
  return ctx ? (ctx.issues.length ? ["Nên sửa gì trước?", "Điểm này nghĩa là gì?", "Cho mình prompt để AI sửa", "Website mình có bị hack không?"] : ["Điểm này nghĩa là gì?", "Quét lại bao giờ?", "Gặp người thật"])
    : ["VibeSec làm gì?", "Quét có an toàn không?", "Mỗi ngày quét được mấy lần?", "Gặp người thật"];
}

function explainIssue(f: Finding, ctx: BotContext): BotReply {
  const fy = FEYNMAN[f.ruleId];
  const title = PLAIN_TITLES[f.ruleId] ?? f.title;
  const text = [
    `🔎 ${title}`,
    fy ? `Hình dung nhé: ${fy.like}` : f.summary,
    fy ? `Việc cần làm: ${fy.todo}` : "",
    `Mức độ: ${PLAIN_SEV[f.severity] ?? f.severity}.`,
    "Mình soạn sẵn prompt bên dưới, bạn dán vào Cursor / Claude Code là nó tự tìm và sửa giúp bạn.",
  ].filter(Boolean).join("\n");
  return { text, chips: ["Nên sửa gì trước?", "Cho mình prompt cho tất cả"], copy: { label: "Copy prompt cho AI", text: buildFixPrompt(f, ctx.host, ctx.platforms) } };
}

/** Trả lời theo ĐÚNG mục đang chọn, từ giải thích cụ thể của chính mục đó. Không dùng AI. */
export function answerFocused(input: string, focus: Focus): BotReply {
  const f = focus.finding, e = explain(f, focus.host), q = strip(input);
  const impact = IMPACT[f.ruleId];
  const steps = e.steps.map((s, i) => `${i + 1}. [${ROLE_LABEL[s.who]}] ${s.text}`).join("\n");
  const chips = ["Vì sao đây là vấn đề?", "Nguy hiểm đến mức nào?", "Làm gì để sửa?", "Có chắc là đúng không?"];
  const prompt = { label: "Copy prompt cho AI", text: buildFixPrompt(f, focus.host, []) };
  const head = `🔎 ${f.title}`;
  if (focus.line && has(q, "dong nay", "nghia la gi", "hieu", "bang chung", "giai thich", "la gi")) {
    const note = e.notes.find((n) => n.line === focus.line)?.note ?? "Giá trị quan sát được trực tiếp từ phản hồi.";
    return { text: `${head}\n\nDòng bạn chọn:\n${focus.line}\n\n→ ${note}\n\nVì sao nó chứng minh vấn đề: ${e.why}`, chips };
  }
  if (has(q, "vi sao", "tai sao", "sao lai", "why", "co van de gi")) return { text: `${head}\n\nVì sao đây là vấn đề: ${e.why}\n\nVới website của bạn: ${e.consequence}`, chips };
  if (has(q, "nghiem trong", "nguy hiem", "gap", "muc do", "co sao khong", "anh huong")) {
    const u = URGENCY_LABEL[urgencyFor(f.ruleId, f.severity)];
    return { text: `${head}\n\nMức độ: ${PLAIN_SEV[f.severity] ?? f.severity} · ${u}.${impact ? `\n\nTrong 1 ngày: ${impact.today}\nXấu nhất: ${impact.worst}\nAi khai thác được: ${impact.who}` : `\n\n${e.consequence}`}`, chips };
  }
  if (has(q, "lam gi", "sua", "khac phuc", "fix", "lam sao", "cach", "phai lam")) return { text: `${head}\n\nCác bước:\n${steps}\n\nSửa đúng thì: ${e.expect}`, chips, copy: prompt };
  if (has(q, "bao nham", "co dung khong", "chac chan", "tin cay", "sai khong")) {
    const repro = reproFor(f.ruleId, focus.host);
    return { text: `${head}\n\nĐộ tin cậy của phát hiện này: ${f.confidence === "high" ? "cao" : f.confidence === "medium" ? "vừa" : "thấp"}.\n${repro ? `Bạn có thể tự kiểm chứng bằng lệnh chỉ-đọc này:\n${repro}\n\n` : ""}Nếu kết quả khác với bằng chứng ở trên thì báo cho mình để kiểm tra lại.`, chips };
  }
  if (has(q, "kiem tra lai", "xac minh", "verify", "tai hien")) {
    const repro = reproFor(f.ruleId, focus.host);
    return { text: `${head}\n\n${repro ? `Lệnh tự tái hiện (chỉ đọc):\n${repro}\n\n` : ""}Sửa đúng thì: ${e.expect}`, chips };
  }
  return { text: `${head}\n\nChúng tôi thấy: ${e.saw}\n\nVì sao đây là vấn đề: ${e.why}\n\nCác bước:\n${steps}`, chips, copy: prompt };
}

export function reply(input: string, ctx: BotContext | null, focus?: Focus | null): BotReply {
  if (focus) {
    const q0 = strip(input);
    // Người dùng chủ động xin gặp người thật hoặc hỏi chung về sản phẩm thì không ép vào mục đang chọn.
    if (!has(q0, "nguoi that", "admin", "ho tro", "lien he", "nhan vien", "gop y", "vibesec la gi", "han muc", "bao nhieu lan")) return answerFocused(input, focus);
  }
  const q = strip(input);
  const chips = chipsFor(ctx);

  if (has(q, "nguoi that", "admin", "ho tro", "lien he", "nhan vien", "feedback", "gop y")) {
    return { text: "Được chứ! Mình chuyển bạn sang đội ngũ thật nhé 💌 Bạn nhắn ở khung bên dưới, họ sẽ trả lời bạn sớm.", chips: [], handoff: true };
  }
  if (/^(hi|hello|alo|chao|xin chao|hey)\b/.test(q)) return { text: GREETING, chips };

  if (ctx) {
    if (has(q, "prompt", "cursor", "claude", "copilot", "chatgpt", "ai code", "nho ai", "dan vao")) {
      if (!ctx.issues.length) return { text: "Website của bạn chưa có vấn đề cần sửa nên mình chưa cần soạn prompt nào hết 🎉", chips };
      const hit = ctx.issues.find((f) => words(`${PLAIN_TITLES[f.ruleId] ?? ""} ${f.title}`).filter((w) => q.includes(w)).length >= 1);
      if (hit && !has(q, "tat ca")) return explainIssue(hit, ctx);
      return { text: `Xong rồi nè! Đây là prompt gộp ${Math.min(ctx.issues.length, 12)} vấn đề, đã xếp từ nguy hiểm nhất. Bạn bấm copy rồi dán vào công cụ AI viết code đang mở dự án của bạn nhé ✨\n\nMuốn prompt cho từng vấn đề riêng thì bạn mở vấn đề đó trong báo cáo, có nút “Copy prompt cho AI”.`, chips: ["Nên sửa gì trước?"], copy: { label: "Copy prompt cho tất cả", text: buildAllPrompt(ctx.issues, ctx.host, ctx.platforms) } };
    }
    if (has(q, "sua gi truoc", "bat dau", "uu tien", "lam gi truoc", "nen sua")) {
      if (!ctx.issues.length) return { text: "Không có gì cần sửa gấp luôn 🎉 Bạn chỉ cần quét lại định kỳ thôi.", chips };
      const top = ctx.issues.slice(0, 3);
      const lines = top.map((f, i) => `${i + 1}. ${PLAIN_TITLES[f.ruleId] ?? f.title}\n   → ${FEYNMAN[f.ruleId]?.todo ?? f.remediation?.summary ?? "Xem chi tiết trong báo cáo."}`);
      return { text: `Mình xếp theo độ nguy hiểm, bạn làm từ trên xuống nhé:\n\n${lines.join("\n\n")}\n\nBạn hỏi mình “vấn đề số 1 là gì” để mình giải thích kỹ hơn, hoặc xin prompt cho AI sửa luôn.`, chips: ["Cho mình prompt cho tất cả", "Điểm này nghĩa là gì?"] };
    }
    if (has(q, "diem", "score", "hang", "bao nhieu diem")) {
      const urgent = ctx.issues.filter((f) => f.severity === "critical" || f.severity === "high").length;
      return { text: `${plainScore(ctx.score, ctx.issues.length, urgent)}\n\n(Quét từ bên ngoài không bao giờ cho 100 điểm, vì mình không nhìn được bên trong máy chủ của bạn.)`, chips };
    }
    if (has(q, "bi hack", "an toan khong", "co an toan")) {
      return { text: "Mình chỉ nhìn website từ bên ngoài giống như một người khách đi ngang, nên không thể khẳng định tuyệt đối là “an toàn” hay “đã bị hack”. Điểm số chỉ cho biết các cánh cửa ngoài đã khoá chắc chưa. Nếu bạn nghi bị xâm nhập thật, hãy nhắn đội hỗ trợ nhé.", chips: [...chips.slice(0, 2), "Gặp người thật"] };
    }
    // khớp vấn đề theo từ khoá
    const qw = new Set(words(input));
    let best: { f: Finding; n: number } | null = null;
    for (const f of ctx.issues) {
      const n = words(`${PLAIN_TITLES[f.ruleId] ?? ""} ${f.title} ${f.ruleId.replace(/[.-]/g, " ")}`).filter((w) => qw.has(w)).length;
      if (n && (!best || n > best.n)) best = { f, n };
    }
    const ord = q.match(/(?:so|thu|#)\s*(\d)/);
    if (ord && ctx.issues[Number(ord[1]) - 1]) return explainIssue(ctx.issues[Number(ord[1]) - 1]!, ctx);
    if (best) return explainIssue(best.f, ctx);
  }

  // thuật ngữ
  for (const [term, meaning] of Object.entries(GLOSSARY)) {
    if (new RegExp(`(^|[^a-z0-9])${strip(term).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^a-z0-9]|$)`).test(q)) return { text: `📘 ${term} là gì?\n${meaning}`, chips };
  }

  if (has(q, "vibesec la gi", "lam gi", "dung de lam gi")) return { text: "VibeSec như một người khách tò mò đi quanh website của bạn và thử xem cửa nào chưa khoá, rồi nói cho bạn bằng ngôn ngữ dễ hiểu, kèm cách sửa. Mình không phá hay tấn công gì cả 🐾", chips };
  if (has(q, "an toan", "pha", "tan cong", "hai website")) return { text: "Yên tâm nha: mình chỉ xem những gì ai cũng thấy được, không dò mật khẩu, không gửi mã khai thác, và chỉ quét website công khai.", chips };
  if (has(q, "han muc", "bao nhieu lan", "may lan", "gioi han", "mot ngay")) return { text: "Mỗi bạn được quét tối đa 3 lần mỗi ngày (và 2 lần mỗi giờ) để hệ thống luôn chạy mượt cho mọi người. Quét lại cùng một địa chỉ trong thời gian ngắn thì mình dùng lại kết quả, không tốn lượt nhé.", chips };
  if (has(q, "quet lai", "khi nao quet")) return { text: "Sửa xong, đợi khoảng 1 phút cho bộ nhớ đệm cập nhật rồi bấm “Quét lại” nhé. Nên quét lại mỗi khi bạn đổi hosting hoặc cập nhật website.", chips };
  if (has(q, "cam on", "thanks", "tuyet")) return { text: "Hihi, rất vui được giúp bạn 💙 Cần gì cứ hỏi mình nha!", chips };

  return { text: "Hmm, câu này mình chưa hiểu lắm 🙈 Bạn thử chọn một gợi ý bên dưới, hỏi về một thuật ngữ (như HTTPS, CSP, cookie), hoặc bấm “Gặp người thật” để nhắn đội hỗ trợ nhé.", chips: [...chips.slice(0, 3), "Gặp người thật"] };
}
