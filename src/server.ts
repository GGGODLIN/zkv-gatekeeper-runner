import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  evaluateGatekeeperRules,
  proveGatekeeperDecision,
} from "./gatekeeper.ts";
import { signOutboundHmac, verifyInboundHmac } from "./hmac.ts";
import { GatekeeperStore } from "./store.ts";
import {
  GatekeeperTaskEnvelopeSchema,
  PreflightEnvelopeSchema,
  resolveReasonCode,
} from "./types.ts";

const DEFAULT_SOFT_DEADLINE_MS = 45_000;

async function readRawBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function sendSignedJson(
  res: http.ServerResponse,
  statusCode: number,
  rawJson: string,
  hmacSecret: string,
): void {
  const signature = signOutboundHmac(rawJson, hmacSecret);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "x-agent-games-signature": signature,
  });
  res.end(rawJson);
}

export async function createGatekeeperServer(options: {
  port?: number;
  host?: string;
  hmacSecret: string;
  dbPath: string;
  wasmPath: string;
  zkeyPath: string;
  vkPath: string;
  reasonCodeProfile?: "event_page" | "canonical_rules";
  softDeadlineMs?: number;
  log?: (line: string) => void;
}): Promise<{
  url: string;
  port: number;
  close: () => Promise<void>;
}> {
  if (!options.hmacSecret) {
    throw new Error("AGENT_GAMES_HMAC_SECRET is required");
  }

  const profile = options.reasonCodeProfile ?? "event_page";
  const softDeadlineMs = options.softDeadlineMs ?? DEFAULT_SOFT_DEADLINE_MS;
  const log =
    options.log ??
    ((line: string) => {
      process.stderr.write(`${line}\n`);
    });

  const vkJson = JSON.parse(
    fs.readFileSync(options.vkPath, "utf8"),
  ) as Record<string, unknown>;
  const store = new GatekeeperStore(options.dbPath);

  const handleAgentPost = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    const requestStartedMs = Date.now();
    const rawBody = await readRawBody(req);

    // Verify raw-body HMAC BEFORE parsing JSON
    const sigOk = verifyInboundHmac(
      rawBody,
      req.headers["x-agent-games-signature"],
      options.hmacSecret,
    );
    if (!sigOk) {
      sendSignedJson(
        res,
        401,
        JSON.stringify({ error: "Invalid HMAC signature" }),
        options.hmacSecret,
      );
      return;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendSignedJson(
        res,
        200,
        JSON.stringify({
          decision: "REJECT",
          reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
        }),
        options.hmacSecret,
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
      );
      return;
    }

    const taskParse = GatekeeperTaskEnvelopeSchema.safeParse(parsedJson);
    if (!taskParse.success) {
      sendSignedJson(
        res,
        200,
        JSON.stringify({
          decision: "REJECT",
          reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
        }),
        options.hmacSecret,
      );
      return;
    }

    const task = taskParse.data;
    const rawBodySha256 = crypto
      .createHash("sha256")
      .update(rawBody)
      .digest("hex");

    const precheck = store.precheckTask(
      task.task_id,
      rawBodySha256,
      task.mode,
      task.input.proof_tx,
    );

    if (precheck.status === "CACHED") {
      sendSignedJson(res, 200, precheck.responseJson, options.hmacSecret);
      return;
    }

    if (precheck.status === "TASK_ID_CONFLICT") {
      sendSignedJson(
        res,
        200,
        JSON.stringify({
          decision: "REJECT",
          reason_code: resolveReasonCode("INVALID_PAYLOAD", profile),
          proof_tx: task.input.proof_tx,
        }),
        options.hmacSecret,
      );
      return;
    }

    if (precheck.status === "PROOF_REUSED") {
      const json = JSON.stringify({
        decision: "REJECT",
        reason_code: resolveReasonCode("PROOF_REUSED", profile),
        proof_tx: task.input.proof_tx,
      });
      store.recordRejectedTask(task.task_id, rawBodySha256, json);
      sendSignedJson(res, 200, json, options.hmacSecret);
      return;
    }

    const evaluation = evaluateGatekeeperRules(task, Date.now());
    let decision: "APPROVE" | "REJECT" = evaluation.decision;
    let reasonCode = resolveReasonCode(evaluation.reasonKey, profile);
    let proved: {
      proof: Record<string, unknown>;
      publicSignals: string[];
    } | null = null;

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

    const outBody = {
      decision,
      reason_code: reasonCode,
      proof_tx: task.input.proof_tx,
      ...(proved?.proof ? { proof: proved.proof } : {}),
      ...(proved?.publicSignals
        ? { public_signals: proved.publicSignals }
        : {}),
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
      const json = JSON.stringify({
        decision: "REJECT",
        reason_code: resolveReasonCode("PROOF_REUSED", profile),
        proof_tx: task.input.proof_tx,
      });
      store.recordRejectedTask(task.task_id, rawBodySha256, json);
      sendSignedJson(res, 200, json, options.hmacSecret);
      return;
    }

    sendSignedJson(res, 200, committed.responseJson, options.hmacSecret);
  };

  const server = http.createServer((req, res) => {
    const reqUrl = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? "127.0.0.1"}`,
    );
    const pathname = reqUrl.pathname;

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
          sendSignedJson(
            res,
            500,
            JSON.stringify({ error: "Internal server error" }),
            options.hmacSecret,
          );
        }
      });
      return;
    }

    sendSignedJson(
      res,
      404,
      JSON.stringify({ error: "Not found" }),
      options.hmacSecret,
    );
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

function loadEnvFromProcess() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, "..");

  const hmacSecret = process.env.AGENT_GAMES_HMAC_SECRET?.trim() ?? "";
  if (!hmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET environment variable must be set",
    );
  }

  const rawProfile = process.env.REASON_CODE_PROFILE ?? "event_page";
  const reasonCodeProfile: "event_page" | "canonical_rules" =
    rawProfile === "canonical_rules" ? "canonical_rules" : "event_page";

  const port = Number.parseInt(process.env.PORT ?? "3411", 10);
  const softDeadlineMs = Number.parseInt(
    process.env.SOFT_DEADLINE_MS ?? String(DEFAULT_SOFT_DEADLINE_MS),
    10,
  );

  return {
    port: Number.isFinite(port) ? port : 3411,
    host: process.env.HOST ?? "127.0.0.1",
    hmacSecret,
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
  };
}

const isEntrypoint =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isEntrypoint) {
  const opts = loadEnvFromProcess();
  const handle = await createGatekeeperServer(opts);
  process.stdout.write(
    `${JSON.stringify({
      event: "server_started",
      url: handle.url,
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
