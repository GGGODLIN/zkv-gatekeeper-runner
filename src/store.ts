import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export class GatekeeperStore {
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath !== ":memory:") {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS task_cache (
        task_id TEXT PRIMARY KEY,
        raw_body_sha256 TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen_proofs (
        mode TEXT NOT NULL,
        proof_tx TEXT NOT NULL,
        first_task_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (mode, proof_tx)
      );
    `);
  }

  private runImmediate<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const out = fn();
      this.db.exec("COMMIT;");
      return out;
    } catch (err: unknown) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {
        // Ignore rollback failure when transaction never opened or already aborted
      }
      throw err;
    }
  }

  public precheckTask(
    taskId: string,
    rawBodySha256: string,
    mode: "practice" | "competition",
    proofTx: string,
  ):
    | { status: "CACHED"; responseJson: string }
    | { status: "TASK_ID_CONFLICT" }
    | { status: "PROOF_REUSED" }
    | { status: "MISS" } {
    return this.runImmediate(() => {
      // Idempotency cache MUST be checked before seen_proofs so network retries never self-trigger PROOF_REUSED.
      const cached = this.db
        .prepare(
          "SELECT raw_body_sha256, response_json FROM task_cache WHERE task_id = ?",
        )
        .get(taskId) as
        | { raw_body_sha256: string; response_json: string }
        | undefined;

      if (cached) {
        if (cached.raw_body_sha256 === rawBodySha256) {
          return { status: "CACHED", responseJson: cached.response_json };
        }
        return { status: "TASK_ID_CONFLICT" };
      }

      const seen = this.db
        .prepare(
          "SELECT 1 AS found FROM seen_proofs WHERE mode = ? AND proof_tx = ?",
        )
        .get(mode, proofTx) as { found: number } | undefined;

      if (seen) {
        return { status: "PROOF_REUSED" };
      }

      return { status: "MISS" };
    });
  }

  public recordRejectedTask(
    taskId: string,
    rawBodySha256: string,
    responseJson: string,
  ): void {
    const now = new Date().toISOString();
    this.runImmediate(() => {
      this.db
        .prepare(
          "INSERT OR IGNORE INTO task_cache (task_id, raw_body_sha256, response_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .run(taskId, rawBodySha256, responseJson, now);
    });
  }

  public commitTaskOutcome(params: {
    taskId: string;
    rawBodySha256: string;
    mode: "practice" | "competition";
    proofTx: string;
    decision: "APPROVE" | "REJECT";
    responseJson: string;
  }):
    | { status: "CACHED"; responseJson: string }
    | { status: "PROOF_REUSED" }
    | { status: "COMMITTED"; responseJson: string } {
    const now = new Date().toISOString();
    return this.runImmediate(() => {
      const existing = this.db
        .prepare(
          "SELECT raw_body_sha256, response_json FROM task_cache WHERE task_id = ?",
        )
        .get(params.taskId) as
        | { raw_body_sha256: string; response_json: string }
        | undefined;

      if (existing && existing.raw_body_sha256 === params.rawBodySha256) {
        return { status: "CACHED", responseJson: existing.response_json };
      }

      if (params.decision === "APPROVE") {
        const seen = this.db
          .prepare(
            "SELECT 1 AS found FROM seen_proofs WHERE mode = ? AND proof_tx = ?",
          )
          .get(params.mode, params.proofTx) as { found: number } | undefined;

        if (seen) {
          return { status: "PROOF_REUSED" };
        }

        this.db
          .prepare(
            "INSERT INTO seen_proofs (mode, proof_tx, first_task_id, decision, created_at) VALUES (?, ?, ?, ?, ?)",
          )
          .run(
            params.mode,
            params.proofTx,
            params.taskId,
            params.decision,
            now,
          );
      }

      this.db
        .prepare(
          "INSERT OR IGNORE INTO task_cache (task_id, raw_body_sha256, response_json, created_at) VALUES (?, ?, ?, ?)",
        )
        .run(
          params.taskId,
          params.rawBodySha256,
          params.responseJson,
          now,
        );

      return { status: "COMMITTED", responseJson: params.responseJson };
    });
  }

  public close(): void {
    this.db.close();
  }
}
