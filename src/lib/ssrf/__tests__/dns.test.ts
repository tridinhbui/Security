import { describe, expect, it } from "vitest";
import { pinnedLookup, resolvePublicAddresses, type Resolver } from "../dns";

const fixed = (...addrs: string[]): Resolver => async () =>
  addrs.map((address) => ({ address, family: address.includes(":") ? (6 as const) : (4 as const) }));

describe("resolvePublicAddresses", () => {
  it("returns public answers", async () => {
    const r = await resolvePublicAddresses("example.com", fixed("93.184.216.34", "2606:2800:220:1::1"));
    expect(r).toHaveLength(2);
  });
  it.each([["127.0.0.1"], ["10.1.2.3"], ["169.254.169.254"], ["::1"], ["fd00::5"], ["::ffff:10.0.0.1"]])(
    "rejects a host that resolves only to %s",
    async (ip) => {
      await expect(resolvePublicAddresses("evil.example.org", fixed(ip))).rejects.toMatchObject({ code: "non_public_ip" });
    },
  );
  it("rejects mixed public + private answers (rebinding signature)", async () => {
    await expect(resolvePublicAddresses("evil.example.org", fixed("93.184.216.34", "127.0.0.1"))).rejects.toMatchObject({
      code: "dns_mixed_answers",
    });
  });
  it("maps resolver failures and empty answers to dns_failed", async () => {
    const fail: Resolver = async () => {
      throw Object.assign(new Error("x"), { code: "ENOTFOUND" });
    };
    await expect(resolvePublicAddresses("nope.example.org", fail)).rejects.toMatchObject({ code: "dns_failed" });
    await expect(resolvePublicAddresses("nope.example.org", fixed())).rejects.toMatchObject({ code: "dns_failed" });
  });
  it("validates IP literals without calling the resolver", async () => {
    const never: Resolver = async () => {
      throw new Error("resolver must not be called");
    };
    await expect(resolvePublicAddresses("127.0.0.1", never)).rejects.toMatchObject({ code: "non_public_ip" });
    await expect(resolvePublicAddresses("2130706433", never)).rejects.toMatchObject({ code: "non_public_ip" });
    await expect(resolvePublicAddresses("8.8.8.8", never)).resolves.toEqual([{ address: "8.8.8.8", family: 4 }]);
    await expect(resolvePublicAddresses("[2606:4700:4700::1111]", never)).resolves.toHaveLength(1);
  });
});

describe("DNS rebinding", () => {
  it("pins the validated address: a later private answer is never used", async () => {
    let calls = 0;
    // First answer public (passes validation), every later answer private (the rebinding flip).
    const rebinding: Resolver = async () => {
      calls++;
      return [{ address: calls === 1 ? "93.184.216.34" : "127.0.0.1", family: 4 }];
    };
    const validated = await resolvePublicAddresses("rebind.example.org", rebinding);
    const lookup = pinnedLookup(validated);
    const out = await new Promise<string>((res, rej) =>
      lookup("rebind.example.org", {}, (e, a) => (e ? rej(e) : res(a as string))),
    );
    expect(out).toBe("93.184.216.34");
    expect(calls).toBe(1); // no second DNS query happens at connect time
  });
  it("pinnedLookup refuses non-public addresses even if handed one", async () => {
    const lookup = pinnedLookup([{ address: "169.254.169.254", family: 4 }]);
    await expect(
      new Promise((res, rej) => lookup("x", {}, (e, a) => (e ? rej(e) : res(a)))),
    ).rejects.toMatchObject({ code: "ENOTFOUND" });
  });
  it("honours all:true and family filters", async () => {
    const lookup = pinnedLookup([
      { address: "93.184.216.34", family: 4 },
      { address: "2606:2800:220:1::1", family: 6 },
    ]);
    const all = await new Promise<unknown>((res) => lookup("x", { all: true }, (_e, a) => res(a)));
    expect(all).toHaveLength(2);
    const v6 = await new Promise<unknown>((res) => lookup("x", { family: 6 }, (_e, a) => res(a)));
    expect(v6).toBe("2606:2800:220:1::1");
  });
  it("caches validated answers briefly", async () => {
    let calls = 0;
    const r: Resolver = async () => (calls++, [{ address: "93.184.216.34", family: 4 }]);
    const cache = new Map();
    await resolvePublicAddresses("c.example.org", r, cache);
    await resolvePublicAddresses("c.example.org", r, cache);
    expect(calls).toBe(1);
  });
});
