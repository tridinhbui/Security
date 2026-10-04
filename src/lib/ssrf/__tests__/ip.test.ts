import { describe, expect, it } from "vitest";
import { classifyIpString, classifyLiteral, parseIPv4, parseIPv6, parseLegacyIPv4 } from "../ip";

describe("parseIPv4", () => {
  it("parses canonical addresses", () => {
    expect(parseIPv4("1.2.3.4")).toBe(0x01020304n);
    expect(parseIPv4("255.255.255.255")).toBe(0xffffffffn);
  });
  it.each(["1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.-4", "a.b.c.d", "", "1..2.3"])("rejects %s", (s) => {
    expect(parseIPv4(s)).toBeNull();
  });
});

describe("parseLegacyIPv4 (inet_aton forms)", () => {
  it.each([
    ["2130706433", 0x7f000001n],
    ["0x7f000001", 0x7f000001n],
    ["017700000001", 0x7f000001n],
    ["127.1", 0x7f000001n],
    ["0x7f.0.0.1", 0x7f000001n],
    ["0177.0.0.1", 0x7f000001n],
    ["127.0.1", 0x7f000001n],
    ["0xa9fea9fe", 0xa9fea9fen],
  ])("%s", (s, v) => expect(parseLegacyIPv4(s)).toBe(v));
  it.each(["example.com", "1.2.3.4.5", "256.0.0.1", "0x", "4294967296", "08.0.0.1"])("rejects %s", (s) => {
    expect(parseLegacyIPv4(s)).toBeNull();
  });
});

describe("parseIPv6", () => {
  it("handles compression and embedded v4", () => {
    expect(parseIPv6("::1")).toBe(1n);
    expect(parseIPv6("::")).toBe(0n);
    expect(parseIPv6("::ffff:127.0.0.1")).toBe(0xffff7f000001n);
    expect(parseIPv6("[2001:db8::1]")).toBe(0x20010db8000000000000000000000001n);
    expect(parseIPv6("1:2:3:4:5:6:7:8")).toBe(0x00010002000300040005000600070008n);
  });
  it.each(["1::2::3", "1:2:3:4:5:6:7", "12345::", "fe80::1%eth0", "::g", ":::", "1:2:3:4:5:6:7:8:9", "::1.2.3"])("rejects %s", (s) => {
    expect(parseIPv6(s)).toBeNull();
  });
});

describe("classifyIpString — blocked", () => {
  it.each([
    "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "127.0.0.1", "127.255.255.254",
    "169.254.169.254", "169.254.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.0.0.1", "192.0.2.5",
    "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.9", "224.0.0.1", "239.255.255.255", "240.0.0.1",
    "255.255.255.255",
    "::", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "64:ff9b::7f00:1",
    "64:ff9b::808:808", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "fec0::1", "ff02::1", "2001:db8::1",
    "2002:7f00:1::", "2001::1", "100::1", "::127.0.0.1", "3fff::1", "1::1",
  ])("blocks %s", (ip) => expect(classifyIpString(ip).public).toBe(false));
});

describe("classifyIpString — public", () => {
  it.each(["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "172.15.255.255", "100.63.255.255", "100.128.0.1",
    "169.253.1.1", "192.169.0.1", "198.20.0.1", "2606:4700:4700::1111", "2a00:1450:4001::200e"])("allows %s", (ip) => {
    expect(classifyIpString(ip).public).toBe(true);
  });
  it("blocks unparseable input", () => expect(classifyIpString("not-an-ip").public).toBe(false));
});

describe("classifyLiteral", () => {
  it("returns null for hostnames", () => {
    expect(classifyLiteral("example.com")).toBeNull();
    expect(classifyLiteral("123.example.com")).toBeNull();
  });
  it("classifies legacy encodings", () => {
    expect(classifyLiteral("2130706433")?.public).toBe(false);
    expect(classifyLiteral("0x7f.1")?.public).toBe(false);
    expect(classifyLiteral("127.1")?.public).toBe(false);
    expect(classifyLiteral("3232235521")?.public).toBe(false); // 192.168.0.1
    expect(classifyLiteral("[::1]")?.public).toBe(false);
    expect(classifyLiteral("134744072")?.public).toBe(true); // 8.8.8.8
  });
});
