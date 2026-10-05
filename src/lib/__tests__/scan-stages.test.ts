import { describe, expect, it } from "vitest";
import type { ScanStatus } from "../db-types";
import { ALL_STEPS, progressFraction, STAGE_GROUPS, stepStates } from "../scan-stages";

const ORDER: ScanStatus[] = ["queued", "validating", "scanning_transport", "checking_headers", "analyzing_client", "generating_report", "completed"];

describe("giai đoạn quét", () => {
  it("đúng chín bước theo trình tự đã cam kết", () => {
    expect(ALL_STEPS.map((s) => s.id)).toEqual(["init", "resolve", "tls", "headers", "exposure", "client", "config", "score", "report"]);
    expect(ALL_STEPS).toHaveLength(9);
  });
  it("mọi giai đoạn thật của máy chủ đều có nhóm hiển thị tương ứng", () => {
    expect(STAGE_GROUPS.map((g) => g.server)).toEqual(ORDER.slice(0, 6));
  });
  it("tiến độ tăng đơn điệu, từ 0 tới 1, và hoàn tất = 1", () => {
    const f = ORDER.map(progressFraction);
    expect([...f].sort((a, b) => a - b)).toEqual(f);
    expect(f[0]).toBeGreaterThan(0);
    expect(f.at(-1)).toBe(1);
    expect(progressFraction("failed")).toBe(0);
  });
  it("trạng thái bước: chưa tới = chờ, giai đoạn hiện tại = đang quét, đã qua = xong", () => {
    const s = stepStates("analyzing_client");
    expect(s).toMatchObject({ init: "done", resolve: "done", tls: "done", headers: "done", exposure: "running", client: "running", config: "pending", score: "pending", report: "pending" });
  });
  it("không bao giờ báo xong trước khi hoàn tất (không giả lập tiến độ)", () => {
    for (const st of ORDER.slice(0, 6)) expect(Object.values(stepStates(st)).every((v) => v === "done")).toBe(false);
    expect(Object.values(stepStates("completed")).every((v) => v === "done")).toBe(true);
  });
  it("tại mỗi thời điểm chỉ một nhóm đang chạy; thứ tự pending → running → done không đảo", () => {
    for (const st of ORDER.slice(0, 6)) {
      const vals = ALL_STEPS.map((x) => stepStates(st)[x.id]);
      const rank = { done: 0, running: 1, pending: 2 } as const;
      const ranks = vals.map((v) => rank[v!]);
      expect([...ranks].sort((a, b) => a - b)).toEqual(ranks);
      expect(new Set(ALL_STEPS.filter((x) => stepStates(st)[x.id] === "running").map((x) => x.server)).size).toBe(1);
    }
  });
  it("trạng thái lạ/failed không đánh dấu bước nào đang chạy", () => {
    expect(Object.values(stepStates("failed")).every((v) => v === "pending")).toBe(true);
  });
});
