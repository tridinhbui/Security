import type { Rule } from "../types";
import { browserRules } from "./browser";
import { configRules } from "./config";
import { cookieRules } from "./cookies";
import { exposureRules } from "./exposure";
import { headerRules } from "./headers";
import { privacyRules } from "./privacy";
import { transportRules } from "./transport";

/**
 * The rule registry. To add a check: write a pure `Rule` in the matching file and add
 * it to that file's exported array — the engine, scoring and UI pick it up with no
 * other changes (the UI renders generic Finding objects, never rule-specific code).
 */
export const ALL_RULES: Rule[] = [
  ...transportRules,
  ...headerRules,
  ...browserRules,
  ...cookieRules,
  ...exposureRules,
  ...configRules,
  ...privacyRules,
];

const ids = new Set<string>();
for (const r of ALL_RULES) {
  if (ids.has(r.id)) throw new Error(`Duplicate rule id: ${r.id}`);
  ids.add(r.id);
}
