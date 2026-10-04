import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { compareScans } from "../compare";
import { decrypt, encrypt, hashIp, hashKey, hashToken, newShareToken, safeEqual } from "../crypto";
import { createDohResolver } from "../ssrf/doh";
import { makeFinding } from "../scanner/util";

beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("base64");
  process.env.IP_HASH_SECRET = "test-secret";
});

describe("crypto (Web Crypto)", () => {
  it("round-trips and uses a fresh IV each time", async () => {
    const a = await encrypt("hello"), b = await encrypt("hello");
    expect(a).not.toBe(b);
    expect(await decrypt(a)).toBe("hello");
    expect(await decrypt(await encrypt("ünïcödé ✓ " + "x".repeat(10000)))).toContain("ünïcödé");
  });
  it("detects tampering and bad formats", async () => {
    const [v, iv, ct] = (await encrypt("secret")).split(":");
    const bytes = Buffer.from(ct!, "base64"); bytes[0] = bytes[0]! ^ 1;
    await expect(decrypt([v, iv, bytes.toString("base64")].join(":"))).rejects.toThrow();
    await expect(decrypt("garbage")).rejects.toThrow();
  });
  it("rejects a wrong-sized key", async () => {
    const prev = process.env.DATA_ENCRYPTION_KEY;
    process.env.DATA_ENCRYPTION_KEY = Buffer.from("short").toString("base64");
    await expect(encrypt("x")).rejects.toThrow(/32/);
    process.env.DATA_ENCRYPTION_KEY = prev;
  });
  it("share tokens are 256-bit, unique, and stored only as a hash", async () => {
    const a = await newShareToken(), b = await newShareToken();
    expect(a.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.token).not.toBe(b.token);
    expect(a.hash).toBe(await hashToken(a.token));
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
  });
  it("keyed hashes are deterministic, domain-separated, and hide the input", async () => {
    expect(await hashIp("1.2.3.4")).toBe(await hashIp("1.2.3.4"));
    expect(await hashIp("1.2.3.4")).not.toBe(await hashIp("1.2.3.5"));
    expect(await hashIp("x")).not.toBe(await hashKey("ip", "x"));
    expect(await hashIp("1.2.3.4")).not.toContain("1.2.3.4");
  });
  it("safeEqual", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    expect(safeEqual("", "")).toBe(true);
  });
});

describe("DoH resolver (Worker preflight)", () => {
  const doh = (answers: Record<string, { Status: number; Answer?: { type: number; data: string }[] }>) =>
    vi.fn(async (url: string | URL | Request) => {
      const u = new URL(String(url));
      return Response.json(answers[u.searchParams.get("type")!] ?? { Status: 0, Answer: [] });
    }) as unknown as typeof fetch;
  it("returns A and AAAA answers", async () => {
    const r = await createDohResolver(doh({ A: { Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }, AAAA: { Status: 0, Answer: [{ type: 28, data: "2606:2800::1" }] } }))("example.com");
    expect(r).toEqual([{ address: "93.184.216.34", family: 4 }, { address: "2606:2800::1", family: 6 }]);
  });
  it("ignores CNAME records in the answer", async () => {
    const r = await createDohResolver(doh({ A: { Status: 0, Answer: [{ type: 5, data: "x.example.net." }, { type: 1, data: "1.2.3.4" }] } }))("example.com");
    expect(r).toEqual([{ address: "1.2.3.4", family: 4 }]);
  });
  it("maps NXDOMAIN to ENOTFOUND and other failures to a transient error", async () => {
    await expect(createDohResolver(doh({ A: { Status: 3 } }))("nope.example")).rejects.toMatchObject({ code: "ENOTFOUND" });
    await expect(createDohResolver(doh({ A: { Status: 2 } }))("x.example")).rejects.toMatchObject({ code: "EDOH" });
    await expect(createDohResolver((async () => new Response("no", { status: 500 })) as unknown as typeof fetch)("x.example")).rejects.toMatchObject({ code: "EDOH" });
  });
});

const F = (ruleId: string, key = "", severity: "high" | "low" | "info" = "high", status: "fail" | "pass" = "fail") =>
  makeFinding({ ruleId, key, title: ruleId, category: "Headers", severity, confidence: "high", status, summary: "s", explanation: "e" });

describe("compareScans", () => {
  it("reports new, resolved and unchanged open findings, ignoring passes and info", () => {
    const prev = { score: 60, findings: [F("a"), F("b"), F("c", "", "info"), F("p", "", "info", "pass")] };
    const curr = { score: 75, findings: [F("b"), F("d"), F("c", "", "info"), F("a", "", "info", "pass")] };
    const r = compareScans(prev, curr);
    expect(r.scoreDelta).toBe(15);
    expect(r.resolvedFindings.map((f) => f.ruleId)).toEqual(["a"]);
    expect(r.newFindings.map((f) => f.ruleId)).toEqual(["d"]);
    expect(r.unchanged).toBe(1);
  });
  it("distinguishes findings by fingerprint key (e.g. per-cookie)", () => {
    const r = compareScans({ score: 50, findings: [F("cookies", "a")] }, { score: 50, findings: [F("cookies", "b")] });
    expect(r.newFindings).toHaveLength(1);
    expect(r.resolvedFindings).toHaveLength(1);
  });
});
