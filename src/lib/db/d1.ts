/**
 * The slice of the D1 API this app uses. Declared structurally so repository code and tests do not
 * depend on Workers runtime types (tests plug in an adapter over node:sqlite).
 */
export interface D1Result<T = unknown> {
  results: T[];
  success: boolean;
  meta: { changes?: number; last_row_id?: number };
}
export interface D1PreparedStatementLike {
  bind(...values: (string | number | null)[]): D1PreparedStatementLike;
  run(): Promise<D1Result>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
}
export interface D1Like {
  prepare(sql: string): D1PreparedStatementLike;
  /** Executed as a single transaction. */
  batch(statements: D1PreparedStatementLike[]): Promise<D1Result[]>;
}

export const nowIso = () => new Date().toISOString();
export const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString();
export const isoIn = (ms: number) => new Date(Date.now() + ms).toISOString();
export const newId = () => crypto.randomUUID();

export const parseJson = <T>(s: unknown, fallback: T): T => {
  if (typeof s !== "string") return fallback;
  try { return JSON.parse(s) as T; } catch { return fallback; }
};
