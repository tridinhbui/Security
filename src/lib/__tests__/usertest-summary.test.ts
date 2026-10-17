import { describe, expect, it } from "vitest";
import { parseCsv, summarize } from "../usertest-summary";

// Dữ liệu dưới đây là FIXTURE KIỂM THỬ CÔNG CỤ, không phải kết quả user testing thật.
const H = "participant_id,group,task,finding_rule,completed,seconds,understanding,owner_correct,fix_found,verify_known,clarity_vote,confusion_note";
const csv = (...rows: string[]) => [H, ...rows].join("\n");

describe("usertest-summary (kiểm thử công cụ, không phải kết quả thật)", () => {
  it("đọc CSV có dấu phẩy trong ngoặc kép và bỏ dòng chú thích", () => {
    const rows = parseCsv(`# chú thích\n${csv('p1,A,T2,headers.csp,1,90,2,2,2,1,clear,"không hiểu ""XSS"", nghĩa là gì"')}`);
    expect(rows).toHaveLength(1); expect(rows[0]!.confusion_note).toBe('không hiểu "XSS", nghĩa là gì');
  });
  it("báo thiếu cột", () => { expect(() => parseCsv("a,b\n1,2")).toThrow(/Thiếu cột/); });
  it("tệp rỗng (chỉ có tiêu đề) không bịa số liệu", () => {
    const s = summarize(parseCsv(csv()));
    expect(s.participants).toBe(0); expect(s.rules).toEqual([]); expect(s.tasks.every((t) => t.n === 0 && t.medianSeconds === null)).toBe(true);
    expect(s.caveats.join(" ")).toMatch(/Chưa có người nhóm A/);
  });
  it("gắn cờ phát hiện bị hiểu sai bởi ≥2 người; 1 người thì chỉ ‘insufficient’", () => {
    const s = summarize(parseCsv(csv(
      "p1,A,T2,headers.csp,1,60,0,0,0,0,unclear,x", "p2,A,T2,headers.csp,1,80,1,0,1,0,unclear,y", "p3,B,T2,tls.hsts,1,40,2,2,2,1,clear,",
      "p1,A,T1,,1,70,,,,,none,", "p2,A,T1,,1,50,,,,,none,", "p3,B,T1,,0,200,,,,,none,")));
    expect(s.rules.find((r) => r.rule === "headers.csp")!.flag).toBe("fix-first");
    expect(s.rules.find((r) => r.rule === "tls.hsts")!.flag).toBe("insufficient");
    const t1 = s.tasks.find((t) => t.task === "T1")!; expect(t1).toMatchObject({ n: 3, completed: 2, medianSeconds: 70 });
    expect(s.caveats[0]).toMatch(/không suy ra tỉ lệ/); expect(s.caveats.join(" ")).toMatch(/3\/5/);
  });
  it("dòng sai định dạng bị loại và liệt kê, không làm hỏng kết quả", () => {
    const s = summarize(parseCsv(csv("p1,Z,T2,x,1,1,1,1,1,1,none,", "p2,A,T9,x,1,1,1,1,1,1,none,", "p3,A,T2,x,1,1,5,1,1,1,none,", "p4,A,T2,x,1,1,2,2,2,1,clear,")));
    expect(s.invalid).toHaveLength(3); expect(s.participants).toBe(1);
  });
});
