import { ALL_RULES } from "./rules";
import type { Finding, Observations, Rule } from "./types";

/** Run every rule. A crashing rule is isolated and reported, never fatal. */
export function evaluate(obs: Observations, rules: Rule[] = ALL_RULES): { findings: Finding[]; errors: string[] } {
  const findings: Finding[] = [];
  const errors: string[] = [];
  for (const rule of rules) {
    try {
      findings.push(...rule.run(obs));
    } catch (e) {
      errors.push(`${rule.id}: ${(e as Error).message}`);
    }
  }
  return { findings, errors };
}
