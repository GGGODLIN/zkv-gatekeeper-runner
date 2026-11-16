import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  evaluateGatekeeperRules,
  OFFICIAL_GATEKEEPER_VK_HASH,
  proveGatekeeperDecision,
} from "./gatekeeper.ts";
import {
  signOutboundHmac,
  verifyInboundHmac,
  type HmacSecretFormat,
} from "./hmac.ts";
import { submitToKurier } from "./kurier.ts";
import { GatekeeperStore } from "./store.ts";
import {
  GatekeeperTaskEnvelopeSchema,
  PreflightEnvelopeSchema,
  resolveReasonCode,
  type GatekeeperResponse,
  type GatekeeperServerHandle,
  type GatekeeperServerOptions,
  type ReasonCodeProfile,
} from "./types.ts";

const MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_SOFT_DEADLINE_MS = 45_000;
const DEFAULT_KURIER_TIMEOUT_MS = 10_000;

class PayloadTooLargeError extends Error {
  constructor() {
    super("Request body exceeds limit");
  }
}

async function readRawBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new PayloadTooLargeError();
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function sendSignedJson(
  res: http.ServerResponse,
  statusCode: number,
  rawJson: string,
  hmacSecret: string,
  hmacFormat: "utf8" | "hex",
): void {
  const signature = signOutboundHmac(rawJson, hmacSecret, hmacFormat);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "x-agent-games-signature": signature,
  });
  res.end(rawJson);
}

function sendUnsignedJson(
  res: http.ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
): void {
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(payload));
}

function extractProofTx(raw: unknown): string | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const input = (raw as { input?: unknown }).input;
  if (typeof input !== "object" || input === null) return undefined;
  const proofTx = (input as { proof_tx?: unknown }).proof_tx;
  return typeof proofTx === "string" && proofTx.trim().length > 0
    ? proofTx.trim()
    : undefined;
}

class KeyedMutex {
  private readonly queues = new Map<string, Promise<void>>();

  public async run<T>(keys: readonly string[], fn: () => Promise<T>): Promise<T> {
    const uniqueSorted = [...new Set(keys)].sort();
    return this.acquireAndRun(uniqueSorted, 0, fn);
  }

  private async acquireAndRun<T>(
    keys: readonly string[],
    idx: number,
    fn: () => Promise<T>,
  ): Promise<T> {
    if (idx >= keys.length) {
      return fn();
    }
    const key = keys[idx];
    const prior = this.queues.get(key) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = prior.then(() => next, () => next);
    this.queues.set(key, tail);

    await prior;
    try {
      return await this.acquireAndRun(keys, idx + 1, fn);
    } finally {
      release();
      if (this.queues.get(key) === tail) {
        this.queues.delete(key);
      }
    }
  }
}

export async function createGatekeeperServer(
  options: GatekeeperServerOptions,
): Promise<GatekeeperServerHandle> {
  if (!options.hmacSecret) {
    throw new Error("AGENT_GAMES_HMAC_SECRET is required");
  }

  const profile: ReasonCodeProfile =
    options.reasonCodeProfile ?? "event_page";
  const inboundFormat: HmacSecretFormat = options.hmacSecretFormat ?? "auto";
  const outboundFormat: "utf8" | "hex" =
    options.hmacSecretFormat === "hex" ? "hex" : "utf8";
  const softDeadlineMs = options.softDeadlineMs ?? DEFAULT_SOFT_DEADLINE_MS;
  const kurierTimeoutMs = options.kurierTimeoutMs ?? DEFAULT_KURIER_TIMEOUT_MS;
  const log =
    options.log ??
    ((line: string) => {
      process.stderr.write(`${line}\n`);
    });

  const vkJson = JSON.parse(
    fs.readFileSync(options.vkPath, "utf8"),
  ) as Record<string, unknown>;
  const store = new GatekeeperStore(options.dbPath);
  const mutex = new KeyedMutex();
  const inboundSecrets = options.hmacSecretPrevious
    ? [options.hmacSecret, options.hmacSecretPrevious]
    : [options.hmacSecret];

  const handleAgentPost = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    const requestStartedMs = Date.now();
    let rawBody: Buffer;
    try {
      rawBody = await readRawBody(req);
    } catch (err: unknown) {
      if (err instanceof PayloadTooLargeError) {
        sendUnsignedJson(res, 413, { error: "Payload too large" });
        return;
      }
      sendUnsignedJson(res, 400, { error: "Failed to read request body" });
      return;
    }

    // Verify raw-body HMAC BEFORE parsing JSON
    const sigOk = verifyInboundHmac(
      rawBody,
      req.headers["x-agent-games-signature"],
      inboundSecrets,
      inboundFormat,
    );
    if (!sigOk) {
      sendUnsignedJson(res, 401, { error: "Invalid HMAC signature" });
      return;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawBody.toString("utf8"));
    } catch {
      const failBody: GatekeeperResponse = {
        decision: "REJECT",
        reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
      };
      sendSignedJson(
        res,
        200,
        JSON.stringify(failBody),
        options.hmacSecret,
        outboundFormat,
      );
      return;
    }

    const preflight = PreflightEnvelopeSchema.safeParse(parsedJson);
    if (preflight.success) {
      sendSignedJson(
        res,
        200,
        JSON.stringify({ ok: true, protocolVersion: "v1" }),
        options.hmacSecret,
        outboundFormat,
      );
      return;
    }

    const taskParse = GatekeeperTaskEnvelopeSchema.safeParse(parsedJson);
    if (!taskParse.success) {
      const proofTx = extractProofTx(parsedJson);
      const failBody: GatekeeperResponse = {
        decision: "REJECT",
        reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
        ...(proofTx !== undefined ? { proof_tx: proofTx } : {}),
      };
      sendSignedJson(
        res,
        200,
        JSON.stringify(failBody),
        options.hmacSecret,
        outboundFormat,
      );
      return;
    }

    const task = taskParse.data;
    const rawBodySha256 = crypto
      .createHash("sha256")
      .update(rawBody)
      .digest("hex");

    const responseJson = await mutex.run(
      [`task:${task.task_id}`, `proof:${task.mode}:${task.input.proof_tx}`],
      async () => {
        const precheck = store.precheckTask(
          task.task_id,
          rawBodySha256,
          task.mode,
          task.input.proof_tx,
        );

        if (precheck.status === "CACHED") {
          return precheck.responseJson;
        }

        if (precheck.status === "TASK_ID_CONFLICT") {
          const conflictBody: GatekeeperResponse = {
            decision: "REJECT",
            reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
            proof_tx: task.input.proof_tx,
          };
          return JSON.stringify(conflictBody);
        }

        if (precheck.status === "PROOF_REUSED") {
          const reusedBody: GatekeeperResponse = {
            decision: "REJECT",
            reason_code: resolveReasonCode("PROOF_REUSED", profile),
            proof_tx: task.input.proof_tx,
          };
          const json = JSON.stringify(reusedBody);
          store.recordRejectedTask(task.task_id, rawBodySha256, json);
          return json;
        }

        const evaluation = evaluateGatekeeperRules(task, Date.now());
        let decision: "APPROVE" | "REJECT" = evaluation.decision;
        let reasonCode = resolveReasonCode(evaluation.reasonKey, profile);
        let proved:
          | { proof: GatekeeperResponse["proof"]; publicSignals: string[] }
          | null = null;

        const elapsedMs = Date.now() - requestStartedMs;
        const remainingForProve = Math.max(1_000, softDeadlineMs - elapsedMs);

        if (evaluation.circuitProvable) {
          try {
            const proveRes = await proveGatekeeperDecision({
              taskId: task.task_id,
              evaluation,
              wasmPath: options.wasmPath,
              zkeyPath: options.zkeyPath,
              vk: vkJson,
              timeoutMs: remainingForProve,
            });
            if (proveRes) {
              proved = {
                proof: proveRes.proof,
                publicSignals: proveRes.publicSignals,
              };
            } else {
              decision = "REJECT";
              reasonCode = resolveReasonCode("INVALID_PAYLOAD", profile);
            }
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            log(
              JSON.stringify({
                level: "warn",
                event: "gatekeeper_prove_failed",
                task_id: task.task_id,
                detail: msg,
              }),
            );
            decision = "REJECT";
            reasonCode = resolveReasonCode("INVALID_PAYLOAD", profile);
          }
        }

        let kurierJobId: string | undefined;
        if (
          options.kurierApiKey &&
          proved?.proof &&
          proved.publicSignals &&
          decision === "APPROVE"
        ) {
          const budgetLeft = softDeadlineMs - (Date.now() - requestStartedMs);
          if (budgetLeft > 1_000) {
            const kurierRes = await submitToKurier({
              apiKey: options.kurierApiKey,
              apiUrl: options.kurierApiUrl,
              proof: proved.proof,
              publicSignals: proved.publicSignals,
              timeoutMs: Math.min(kurierTimeoutMs, budgetLeft - 500),
              log,
            });
            if (kurierRes) {
              kurierJobId = kurierRes.jobId;
            }
          }
        }

        const outBody: GatekeeperResponse = {
          decision,
          reason_code: reasonCode,
          proof_tx: task.input.proof_tx,
          ...(proved?.proof ? { proof: proved.proof } : {}),
          ...(proved?.publicSignals
            ? { public_signals: proved.publicSignals }
            : {}),
          ...(kurierJobId ? { kurier_job_id: kurierJobId } : {}),
        };

        const committed = store.commitTaskOutcome({
          taskId: task.task_id,
          rawBodySha256,
          mode: task.mode,
          proofTx: task.input.proof_tx,
          decision,
          responseJson: JSON.stringify(outBody),
        });

        if (committed.status === "PROOF_REUSED") {
          const reusedBody: GatekeeperResponse = {
            decision: "REJECT",
            reason_code: resolveReasonCode("PROOF_REUSED", profile),
            proof_tx: task.input.proof_tx,
          };
          const json = JSON.stringify(reusedBody);
          store.recordRejectedTask(task.task_id, rawBodySha256, json);
          return json;
        }

        return committed.responseJson;
      },
    );

    sendSignedJson(res, 200, responseJson, options.hmacSecret, outboundFormat);
  };

  const server = http.createServer((req, res) => {
    const reqUrl = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "127.0.0.1"}`,
    );
    const pathname = reqUrl.pathname;

    if (req.method === "GET" && pathname === "/healthz") {
      sendUnsignedJson(res, 200, {
        ok: true,
        status: "healthy",
        vk_hash: OFFICIAL_GATEKEEPER_VK_HASH,
        reason_code_profile: profile,
      });
      return;
    }

    if (
      req.method === "GET" &&
      (pathname === "/gatekeeper/agent" || pathname === "/agent")
    ) {
      sendUnsignedJson(res, 200, {
        service: "zkv-gatekeeper-runner",
        event: "Event 01: Proof Gatekeeper",
        protocol: "agent-games.proof-gatekeeper.v1",
        vk_hash: OFFICIAL_GATEKEEPER_VK_HASH,
      });
      return;
    }

    if (
      req.method === "POST" &&
      (pathname === "/gatekeeper/agent" || pathname === "/agent")
    ) {
      void handleAgentPost(req, res).catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        log(
          JSON.stringify({
            level: "error",
            event: "unhandled_agent_error",
            detail: msg,
          }),
        );
        if (!res.headersSent) {
          sendUnsignedJson(res, 500, { error: "Internal server error" });
        }
      });
      return;
    }

    sendUnsignedJson(res, 404, { error: "Not found" });
  });

  const listenPort = options.port ?? 3411;
  const listenHost = options.host ?? "127.0.0.1";

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(listenPort, listenHost, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const actualPort =
    address && typeof address === "object" ? address.port : listenPort;

  return {
    url: `http://${listenHost}:${actualPort}`,
    port: actualPort,
    close: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => {
          store.close();
          resolve();
        });
      });
    },
  };
}

function nonEmptyEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value && value.length > 0 ? value : undefined;
}

function loadEnvFromEnvProcess(): GatekeeperServerOptions {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, "..");

  const hmacSecret = nonEmptyEnv("AGENT_GAMES_HMAC_SECRET");
  if (!hmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET environment variable must be set",
    );
  }

  const rawProfile = process.env.REASON_CODE_PROFILE ?? "event_page";
  const reasonCodeProfile: ReasonCodeProfile =
    rawProfile === "canonical_rules" ? "canonical_rules" : "event_page";

  const rawFormat = process.env.AGENT_GAMES_HMAC_SECRET_FORMAT ?? "auto";
  const hmacSecretFormat: HmacSecretFormat =
    rawFormat === "hex" || rawFormat === "utf8" ? rawFormat : "auto";

  const port = Number.parseInt(process.env.PORT ?? "3411", 10);
  const softDeadlineMs = Number.parseInt(
    process.env.SOFT_DEADLINE_MS ?? String(DEFAULT_SOFT_DEADLINE_MS),
    10,
  );
  const kurierTimeoutMs = Number.parseInt(
    process.env.KURIER_TIMEOUT_MS ?? String(DEFAULT_KURIER_TIMEOUT_MS),
    10,
  );

  return {
    port: Number.isFinite(port) ? port : 3411,
    host: process.env.HOST ?? "127.0.0.1",
    hmacSecret,
    hmacSecretPrevious: nonEmptyEnv("AGENT_GAMES_HMAC_SECRET_PREVIOUS"),
    hmacSecretFormat,
    dbPath: process.env.SQLITE_DB_PATH ?? path.join(repoRoot, "gatekeeper.db"),
    wasmPath:
      process.env.GATEKEEPER_WASM_PATH ??
      path.join(repoRoot, "circuits", "gatekeeper.wasm"),
    zkeyPath:
      process.env.GATEKEEPER_ZKEY_PATH ??
      path.join(repoRoot, "circuits", "gatekeeper_final.zkey"),
    vkPath:
      process.env.GATEKEEPER_VK_PATH ??
      path.join(repoRoot, "circuits", "verification_key.json"),
    reasonCodeProfile,
    softDeadlineMs: Number.isFinite(softDeadlineMs)
      ? softDeadlineMs
      : DEFAULT_SOFT_DEADLINE_MS,
    kurierApiKey: nonEmptyEnv("KURIER_API_KEY"),
    kurierApiUrl: nonEmptyEnv("KURIER_API_URL"),
    kurierTimeoutMs: Number.isFinite(kurierTimeoutMs)
      ? kurierTimeoutMs
      : DEFAULT_KURIER_TIMEOUT_MS,
  };
}

const isEntrypoint =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isEntrypoint) {
  const opts = loadEnvFromEnvProcess();
  const handle = await createGatekeeperServer(opts);
  process.stdout.write(
    `${JSON.stringify({
      event: "server_started",
      url: handle.url,
      vk_hash: OFFICIAL_GATEKEEPER_VK_HASH,
      reason_code_profile: opts.reasonCodeProfile,
    })}\n`,
  );

  const shutdown = async () => {
    await handle.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}
