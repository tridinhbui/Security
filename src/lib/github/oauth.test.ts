import { describe, expect, it } from "vitest";
import { listRepos, openToken, redirectUri } from "./oauth";

describe("github oauth", () => {
  it("redirectUri cho phép localhost, nơi khác dùng siteUrl", () => {
    expect(redirectUri("http://localhost:3111")).toBe("http://localhost:3111/api/github/callback");
    expect(redirectUri("https://evil.example")).not.toContain("evil.example");
  });
  it("cookie giả mạo bị từ chối", async () => {
    expect(await openToken(undefined)).toBeNull();
    expect(await openToken("not-a-valid-cookie")).toBeNull();
  });
  it("listRepos ánh xạ phản hồi và trả null khi lỗi", async () => {
    const ok = (async () => new Response(JSON.stringify([{ full_name: "a/b", private: true, pushed_at: null }]))) as unknown as typeof fetch;
    expect(await listRepos("t", ok)).toEqual([{ name: "a/b", private: true, pushedAt: null }]);
    expect(await listRepos("t", (async () => new Response("", { status: 401 })) as unknown as typeof fetch)).toBeNull();
  });
});
