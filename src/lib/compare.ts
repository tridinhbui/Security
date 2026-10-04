import type { Finding } from "./scanner/types";

export interface Comparison {
  scoreDelta: number;
  previousScore: number;
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchanged: number;
}

const open = (list: Finding[]) => list.filter((f) => f.status === "fail" && f.severity !== "info");

/** Diff two scans of the same site by finding fingerprint (rule + affected target). */
export function compareScans(prev: { score: number; findings: Finding[] }, curr: { score: number; findings: Finding[] }): Comparison {
  const before = new Map(open(prev.findings).map((f) => [f.fingerprint, f]));
  const after = new Map(open(curr.findings).map((f) => [f.fingerprint, f]));
  const newFindings = [...after.values()].filter((f) => !before.has(f.fingerprint));
  const resolvedFindings = [...before.values()].filter((f) => !after.has(f.fingerprint));
  return {
    scoreDelta: curr.score - prev.score,
    previousScore: prev.score,
    newFindings,
    resolvedFindings,
    unchanged: [...after.keys()].filter((k) => before.has(k)).length,
  };
}
