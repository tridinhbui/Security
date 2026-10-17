import { describe, expect, it } from "vitest";
import { cleanSha, versionInfo } from "../version";

describe("versionInfo", () => {
  it("trả đúng commit, thời điểm build và ID phiên bản Worker", () => {
    expect(versionInfo({ id: "89d80d8d-f991-41cc-89ac-fe53e56db070", tag: "x", timestamp: "2026-10-17T20:10:25Z" }, { sha: "E02E4CB00918AEAC37A2683954F9EC7D83A9F3A9", time: "2026-10-17T20:09:00.000Z" }))
      .toEqual({ commit: "e02e4cb00918aeac37a2683954f9ec7d83a9f3a9", builtAt: "2026-10-17T20:09:00.000Z", workerVersionId: "89d80d8d-f991-41cc-89ac-fe53e56db070", workerVersionUploadedAt: "2026-10-17T20:10:25Z" });
  });
  it("thiếu binding/biến môi trường → null/unknown, không ném lỗi", () => {
    expect(versionInfo(undefined, {})).toEqual({ commit: "unknown", builtAt: "unknown", workerVersionId: null, workerVersionUploadedAt: null });
  });
  it("không bao giờ phản chiếu giá trị lạ (chống lộ cấu hình/chèn nội dung)", () => {
    expect(cleanSha("<script>alert(1)</script>")).toBe("unknown");
    expect(cleanSha("ghp_secrettoken0000000000")).toBe("unknown");
    const v = versionInfo({ id: "not an id with spaces and secrets", timestamp: "token=abc" }, { sha: "xyz", time: "../etc/passwd" });
    expect(v).toEqual({ commit: "unknown", builtAt: "unknown", workerVersionId: null, workerVersionUploadedAt: null });
  });
  it("chỉ có đúng 4 trường", () => {
    expect(Object.keys(versionInfo({ id: "89d80d8d-f991-41cc-89ac-fe53e56db070" }, { sha: "abcdef1" })).sort()).toEqual(["builtAt", "commit", "workerVersionId", "workerVersionUploadedAt"]);
  });
});
