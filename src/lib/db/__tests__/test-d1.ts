import fs from "node:fs";
import path from "node:path";
import { DatabaseSync, type StatementSync } from "node:sqlite";
import type { D1Like, D1PreparedStatementLike, D1Result } from "../d1";

type Param = string | number | null;

/** TEST-ONLY D1 stand-in over node:sqlite (real SQLite semantics: constraints, FKs, RETURNING, transactions). */
export function createTestD1(): D1Like & { sqlite: DatabaseSync } {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  const dir = path.resolve(import.meta.dirname, "../../../../migrations");
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".sql")).sort()) sqlite.exec(fs.readFileSync(path.join(dir, f), "utf8"));

  class Stmt implements D1PreparedStatementLike {
    private params: Param[] = [];
    constructor(private readonly s: StatementSync) {}
    bind(...v: Param[]) { this.params = v; return this; }
    private exec(): D1Result {
      const r = this.s.run(...this.params);
      return { results: [], success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
    }
    async run() { return this.exec(); }
    async first<T>() { return ((this.s.get(...this.params) as T | undefined) ?? null) as T | null; }
    async all<T>() { return { results: this.s.all(...this.params) as T[], success: true, meta: {} } as D1Result<T>; }
    /** @internal used by batch */
    _run() { return this.exec(); }
  }

  return {
    sqlite,
    prepare: (sql: string) => new Stmt(sqlite.prepare(sql)),
    async batch(stmts) {
      sqlite.exec("BEGIN");
      try {
        const out = (stmts as Stmt[]).map((s) => s._run());
        sqlite.exec("COMMIT");
        return out;
      } catch (e) {
        sqlite.exec("ROLLBACK");
        throw e;
      }
    },
  };
}

export async function seedUser(db: D1Like, email: string) {
  const { createUser } = await import("../repo");
  const r = await createUser(db, email, "hash");
  if (!r.ok) throw new Error("seed failed");
  return r.id;
}
