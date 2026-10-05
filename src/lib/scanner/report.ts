import type { Headers, FetchRecord } from "../ssrf/types";
import type { ScoreResult } from "./score";
import type { Finding, Platform } from "./types";

export interface RedactedTarget {
  role: string;
  url: string;
  finalUrl: string;
  status: number | null;
  tls?: FetchRecord["tls"];
  headers: Headers;
  resolved: string[];
  errorCode?: string;
  durationMs: number;
}

export interface ScanReport {
  version: 1;
  /** Phiên bản bộ luật/cách chấm đã tạo báo cáo này (xem version.ts). */
  engineVersion?: number;
  target: { input: string; url: string; host: string };
  scannedAt: string;
  durationMs: number;
  score: ScoreResult;
  findings: Finding[]; // prioritised
  topRisks: Finding[];
  platforms: Platform[];
  technologies: string[];
  targets: RedactedTarget[];
  stats: { requests: number; hitLimit: string | null; rulesRun: number; ruleErrors: string[]; quick?: boolean };
  disclaimer: string;
}

/** Cookie values must never be stored: keep the attributes, drop the value. */
export function redactHeaders(h: Headers): Headers {
  const out: Headers = {};
  for (const [k, v] of Object.entries(h)) {
    if (k === "set-cookie") {
      const list = Array.isArray(v) ? v : [v];
      out[k] = list.map((c) => c.replace(/^([^=;]+)=([^;]*)/, "$1=<đã che>"));
    } else if (/^(authorization|proxy-authorization|cookie|x-api-key)$/i.test(k)) {
      out[k] = "<đã che>";
    } else {
      out[k] = v;
    }
  }
  return out;
}

export class ScanRefusedError extends Error {
  constructor(public readonly code: string, message: string, public readonly detail?: string) {
    super(message);
    this.name = "ScanRefusedError";
  }
}

