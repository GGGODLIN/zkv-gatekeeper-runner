import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

import { createGatekeeperServer } from "../src/server.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const WASM_PATH = path.join(REPO_ROOT, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(REPO_ROOT, "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(REPO_ROOT, "circuits", "verification_key.json");

const PRIMARY_SECRET = "test-hmac-secret-synthetic-0001";
const PREVIOUS_SECRET = "test-hmac-secret-synthetic-prev";
const OFFICIAL_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function signRaw(rawBody: string | Buffer, secret: string): string {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function verifySig(
  rawBody: string,
  sigHeader: string | null,
  secret: string,
): boolean {
  if (!sigHeader) return false;
  const expected = signRaw(rawBody, secret);
  if (sigHeader.length !== expected.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(sigHeader, "hex"),
    Buffer.from(expected, "hex"),
  );
}

function makeTaskPayload(overrides: {
  task_id?: string;
  mode?: "practice" | "competition";
  issued_at?: string;
  deadline_at?: string;
  input?: Record<string, unknown>;
} = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: overrides.task_id ?? `gk_test_${crypto.randomUUID().slice(0, 8)}`,
    mode: overrides.mode ?? "competition",
    issued_at: overrides.issued_at ?? new Date().toISOString(),
    deadline_at:
      overrides.deadline_at ?? new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: "0x7d3a00000000000000000000000000000000f291",
      proof_vk: "0x7d3a00000000000000000000000000000000f291",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0xDe42000000000000000000000000000000009f01",
      condition_recipient: "0xDe42000000000000000000000000000000009f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: `0x${crypto.randomBytes(16).toString("hex")}`,
      ...(overrides.input ?? {}),
    },
  };
}

async function postSigned(
  baseUrl: string,
  route: string,
  rawBody: string,
  signature: string | undefined,
) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (signature !== undefined) {
    headers["x-agent-games-signature"] = signature;
  }
  const res = await fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers,
    body: rawBody,
  });
  const text = await res.text();
  return {
    status: res.status,
    rawBody: text,
    signature: res.headers.get("x-agent-games-signature"),
    json: JSON.parse(text) as Record<string, unknown>,
  };
}

describe("zkv-gatekeeper-runner /gatekeeper/agent acceptance", () => {
  let tmpDir: string;
  let dbPath: string;
  let baseUrl: string;
  let closeServer: () => Promise<void>;
  let officialVk: Record<string, unknown>;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "zkv-gk-test-"));
    dbPath = path.join(tmpDir, "gatekeeper.db");
    officialVk = JSON.parse(fs.readFileSync(VK_PATH, "utf8")) as Record<
      string,
      unknown
    >;

    const handle = await createGatekeeperServer({
      port: 0,
      host: "127.0.0.1",
      hmacSecret: PRIMARY_SECRET,
      hmacSecretPrevious: PREVIOUS_SECRET,
      dbPath,
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      vkPath: VK_PATH,
      reasonCodeProfile: "event_page",
      softDeadlineMs: 45_000,
    });
    baseUrl = handle.url;
    closeServer = handle.close;
  });

  after(async () => {
    await closeServer?.();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    await (globalThis as { curve_bn128?: { terminate(): Promise<void> } })
      .curve_bn128?.terminate();
  });

  it("exposes /healthz with official vk_hash and zero secret leakage", async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const bodyText = await res.text();
    const json = JSON.parse(bodyText) as Record<string, unknown>;
    assert.equal(json.ok, true);
    assert.equal(json.vk_hash, OFFICIAL_VK_HASH);
    assert.equal(
      bodyText.includes(PRIMARY_SECRET),
      false,
      "healthz must not expose HMAC secret",
    );
  });

  it("rejects unsigned, tampered, or bad-HMAC malformed requests with 401 before JSON parsing", async () => {
    const validRaw = JSON.stringify(makeTaskPayload());

    const unsigned = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      validRaw,
      undefined,
    );
    assert.equal(unsigned.status, 401);

    const tampered = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      validRaw,
      signRaw(validRaw + " ", PRIMARY_SECRET),
    );
    assert.equal(tampered.status, 401);

    // Invalid JSON with invalid signature must still fail with 401 (HMAC checked before JSON.parse)
    const badJsonBadHmac = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      "{not-valid-json",
      "deadbeef".repeat(8),
    );
    assert.equal(badJsonBadHmac.status, 401);

    // Invalid JSON with VALID signature fails closed to signed 200 REJECT
    const badJsonValidHmac = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      "{not-valid-json",
      signRaw("{not-valid-json", PRIMARY_SECRET),
    );
    assert.equal(badJsonValidHmac.status, 200);
    assert.equal(badJsonValidHmac.json.decision, "REJECT");
    assert.equal(
      verifySig(badJsonValidHmac.rawBody, badJsonValidHmac.signature, PRIMARY_SECRET),
      true,
    );
  });

  it("handles agent-games.preflight.v1 under 50ms on both /gatekeeper/agent and /agent with signed response", async () => {
    const preflight = JSON.stringify({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test_01",
      issued_at: new Date().toISOString(),
      nonce: "nonce_xyz",
    });

    for (const route of ["/gatekeeper/agent", "/agent"]) {
      const started = performance.now();
      const res = await postSigned(
        baseUrl,
        route,
        preflight,
        `sha256=${signRaw(preflight, PREVIOUS_SECRET)}`,
      );
      const elapsedMs = performance.now() - started;

      assert.equal(res.status, 200);
      assert.deepEqual(res.json, { ok: true, protocolVersion: "v1" });
      assert.equal(
        verifySig(res.rawBody, res.signature, PRIMARY_SECRET),
        true,
        `outbound signature must verify on ${route}`,
      );
      assert.ok(elapsedMs < 50, `preflight took ${elapsedMs.toFixed(1)}ms`);
    }
  });

  it("approves valid condition and generates real Groth16 proof verified by official VK", async () => {
    const payload = makeTaskPayload();
    const raw = JSON.stringify(payload);
    const res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      raw,
      signRaw(raw, PRIMARY_SECRET),
    );

    assert.equal(res.status, 200);
    assert.equal(verifySig(res.rawBody, res.signature, PRIMARY_SECRET), true);
    assert.equal(res.json.decision, "APPROVE");
    assert.equal(res.json.reason_code, "VALID_CONDITION");
    assert.equal(res.json.proof_tx, payload.input.proof_tx);

    const proof = res.json.proof as Record<string, unknown>;
    const publicSignals = res.json.public_signals as string[];
    assert.ok(proof && typeof proof === "object");
    assert.ok(Array.isArray(publicSignals) && publicSignals.length === 13);
    assert.equal(publicSignals[11], "1");

    const verified = await snarkjs.groth16.verify(
      officialVk,
      publicSignals,
      proof,
    );
    assert.equal(verified, true);
  });

  it("deterministically rejects all 5 circuit traps with Groth16 proof and fails closed on missing/malformed/expired-envelope payloads", async () => {
    const trapCases: Array<{
      name: string;
      expectedReason: string;
      inputOverrides: Record<string, unknown>;
    }> = [
      {
        name: "VK_SUBSTITUTION",
        expectedReason: "VK_SUBSTITUTION",
        inputOverrides: {
          proof_vk: "0xa4c100000000000000000000000000000000b8ff",
        },
      },
      {
        name: "THRESHOLD_MISMATCH",
        expectedReason: "THRESHOLD_MISMATCH",
        inputOverrides: {
          minimum: "2000",
          public_balance: "1460",
        },
      },
      {
        name: "EXPIRED_CONDITION (equal block)",
        expectedReason: "EXPIRED_CONDITION",
        inputOverrides: {
          expiry_block: 19832000,
          current_block: 19832000,
        },
      },
      {
        name: "RECIPIENT_MISMATCH",
        expectedReason: "RECIPIENT_MISMATCH",
        inputOverrides: {
          recipient: "0xBad000000000000000000000000000000000dead",
        },
      },
      {
        name: "AMOUNT_OVERFLOW",
        expectedReason: "AMOUNT_OVERFLOW",
        inputOverrides: {
          amount: "1001",
          max_transfer: "1000",
        },
      },
    ];

    for (const tc of trapCases) {
      const payload = makeTaskPayload({ input: tc.inputOverrides });
      const raw = JSON.stringify(payload);
      const res = await postSigned(
        baseUrl,
        "/gatekeeper/agent",
        raw,
        signRaw(raw, PRIMARY_SECRET),
      );

      assert.equal(res.status, 200, tc.name);
      assert.equal(
        verifySig(res.rawBody, res.signature, PRIMARY_SECRET),
        true,
        tc.name,
      );
      assert.equal(res.json.decision, "REJECT", tc.name);
      assert.equal(res.json.reason_code, tc.expectedReason, tc.name);
      assert.equal(res.json.proof_tx, payload.input.proof_tx, tc.name);

      const proof = res.json.proof as Record<string, unknown>;
      const publicSignals = res.json.public_signals as string[];
      assert.ok(Array.isArray(publicSignals) && publicSignals.length === 13);
      assert.equal(publicSignals[11], "0", tc.name);
      const verified = await snarkjs.groth16.verify(
        officialVk,
        publicSignals,
        proof,
      );
      assert.equal(verified, true, `${tc.name} proof must verify`);
    }

    // Missing field -> fail closed REJECT
    const missingFieldRaw = JSON.stringify({
      type: "agent-games.proof-gatekeeper.v1",
      task_id: "gk_missing_01",
      mode: "competition",
      input: { proof_tx: "0x1111" },
    });
    const missingRes = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      missingFieldRaw,
      signRaw(missingFieldRaw, PRIMARY_SECRET),
    );
    assert.equal(missingRes.status, 200);
    assert.equal(missingRes.json.decision, "REJECT");
    assert.equal(
      verifySig(missingRes.rawBody, missingRes.signature, PRIMARY_SECRET),
      true,
    );

    // Expired deadline_at -> fail closed REJECT
    const expiredDeadlinePayload = makeTaskPayload({
      deadline_at: new Date(Date.now() - 5_000).toISOString(),
    });
    const expiredDeadlineRaw = JSON.stringify(expiredDeadlinePayload);
    const expiredRes = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      expiredDeadlineRaw,
      signRaw(expiredDeadlineRaw, PRIMARY_SECRET),
    );
    assert.equal(expiredRes.status, 200);
    assert.equal(expiredRes.json.decision, "REJECT");
    assert.equal(expiredRes.json.reason_code, "EXPIRED_CONDITION");

    // Numeric overflow beyond 64-bit / circuit range -> fail closed REJECT
    const overflowPayload = makeTaskPayload({
      input: {
        expiry_block: "340282366920938463463374607431768211456", // 2^128
      },
    });
    const overflowRaw = JSON.stringify(overflowPayload);
    const overflowRes = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      overflowRaw,
      signRaw(overflowRaw, PRIMARY_SECRET),
    );
    assert.equal(overflowRes.status, 200);
    assert.equal(overflowRes.json.decision, "REJECT");
  });

  it("replays cached signed response on identical (task_id, rawBody) retry, rejects distinct task_id reusing competition proof_tx, and isolates practice from competition", async () => {
    const sharedProofTx = `0x${crypto.randomBytes(16).toString("hex")}`;

    // 1. Practice run with sharedProofTx -> APPROVE (must NOT poison competition)
    const practice1 = makeTaskPayload({
      task_id: "gk_prac_1",
      mode: "practice",
      input: { proof_tx: sharedProofTx },
    });
    const practice1Raw = JSON.stringify(practice1);
    const p1Res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      practice1Raw,
      signRaw(practice1Raw, PRIMARY_SECRET),
    );
    assert.equal(p1Res.json.decision, "APPROVE");

    // 2. Distinct task_id in practice reusing sharedProofTx -> PROOF_REUSED
    const practice2 = makeTaskPayload({
      task_id: "gk_prac_2",
      mode: "practice",
      input: { proof_tx: sharedProofTx },
    });
    const practice2Raw = JSON.stringify(practice2);
    const p2Res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      practice2Raw,
      signRaw(practice2Raw, PRIMARY_SECRET),
    );
    assert.equal(p2Res.json.decision, "REJECT");
    assert.equal(p2Res.json.reason_code, "PROOF_REUSED");

    // 3. Competition task with SAME sharedProofTx -> APPROVE (practice did not contaminate competition)
    const comp1 = makeTaskPayload({
      task_id: "gk_comp_1",
      mode: "competition",
      input: { proof_tx: sharedProofTx },
    });
    const comp1Raw = JSON.stringify(comp1);
    const c1Res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      comp1Raw,
      signRaw(comp1Raw, PRIMARY_SECRET),
    );
    assert.equal(c1Res.json.decision, "APPROVE");
    assert.equal(c1Res.json.reason_code, "VALID_CONDITION");

    // 4. Network retry of comp1 (identical task_id + rawBody) -> exact cached signed response, NOT PROOF_REUSED
    const retryRes = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      comp1Raw,
      signRaw(comp1Raw, PRIMARY_SECRET),
    );
    assert.equal(retryRes.status, 200);
    assert.equal(retryRes.rawBody, c1Res.rawBody);
    assert.equal(retryRes.signature, c1Res.signature);

    // 5. Distinct task_id in competition reusing sharedProofTx -> PROOF_REUSED
    const comp2 = makeTaskPayload({
      task_id: "gk_comp_2",
      mode: "competition",
      input: { proof_tx: sharedProofTx },
    });
    const comp2Raw = JSON.stringify(comp2);
    const c2Res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      comp2Raw,
      signRaw(comp2Raw, PRIMARY_SECRET),
    );
    assert.equal(c2Res.json.decision, "REJECT");
    assert.equal(c2Res.json.reason_code, "PROOF_REUSED");

    // 6. Restart server against the SAME SQLite file and verify idempotency + seen_proofs persist
    await closeServer();
    const reopened = await createGatekeeperServer({
      port: 0,
      host: "127.0.0.1",
      hmacSecret: PRIMARY_SECRET,
      dbPath,
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      vkPath: VK_PATH,
      reasonCodeProfile: "event_page",
      softDeadlineMs: 45_000,
    });
    baseUrl = reopened.url;
    closeServer = reopened.close;

    const retryAfterRestart = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      comp1Raw,
      signRaw(comp1Raw, PRIMARY_SECRET),
    );
    assert.equal(retryAfterRestart.rawBody, c1Res.rawBody);

    const comp3 = makeTaskPayload({
      task_id: "gk_comp_3",
      mode: "competition",
      input: { proof_tx: sharedProofTx },
    });
    const comp3Raw = JSON.stringify(comp3);
    const c3Res = await postSigned(
      baseUrl,
      "/gatekeeper/agent",
      comp3Raw,
      signRaw(comp3Raw, PRIMARY_SECRET),
    );
    assert.equal(c3Res.json.decision, "REJECT");
    assert.equal(c3Res.json.reason_code, "PROOF_REUSED");

    // 7. Concurrent distinct task_ids racing on the same fresh proof_tx -> exactly one APPROVE and one PROOF_REUSED
    const raceProofTx = `0x${crypto.randomBytes(16).toString("hex")}`;
    const raceA = JSON.stringify(
      makeTaskPayload({
        task_id: "gk_race_a",
        mode: "competition",
        input: { proof_tx: raceProofTx },
      }),
    );
    const raceB = JSON.stringify(
      makeTaskPayload({
        task_id: "gk_race_b",
        mode: "competition",
        input: { proof_tx: raceProofTx },
      }),
    );
    const [rA, rB] = await Promise.all([
      postSigned(baseUrl, "/agent", raceA, signRaw(raceA, PRIMARY_SECRET)),
      postSigned(baseUrl, "/agent", raceB, signRaw(raceB, PRIMARY_SECRET)),
    ]);
    const decisions = [rA.json.decision, rB.json.decision].sort();
    assert.deepEqual(decisions, ["APPROVE", "REJECT"]);
    const rejected = rA.json.decision === "REJECT" ? rA : rB;
    assert.equal(rejected.json.reason_code, "PROOF_REUSED");
  });

  it("supports canonical_rules REASON_CODE_PROFILE and scrubs Kurier API key on error/timeout fallback", async () => {
    const syntheticKurierKey = "kurier-synthetic-test-key-0001";
    const capturedLogs: string[] = [];

    // Local HTTP mock representing external Kurier service returning 500
    const kurierServer = http.createServer((req, res) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: `Upstream failure at /submit-proof/${syntheticKurierKey}`,
        }),
      );
    });
    await new Promise<void>((resolve) =>
      kurierServer.listen(0, "127.0.0.1", resolve),
    );
    const kurierAddr = kurierServer.address() as { port: number };
    const kurierBaseUrl = `http://127.0.0.1:${kurierAddr.port}/api/v1`;

    const canonicalDbPath = path.join(tmpDir, "canonical.db");
    const canonicalHandle = await createGatekeeperServer({
      port: 0,
      host: "127.0.0.1",
      hmacSecret: PRIMARY_SECRET,
      dbPath: canonicalDbPath,
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      vkPath: VK_PATH,
      reasonCodeProfile: "canonical_rules",
      kurierApiKey: syntheticKurierKey,
      kurierApiUrl: kurierBaseUrl,
      kurierTimeoutMs: 2_000,
      softDeadlineMs: 45_000,
      log: (line: string) => capturedLogs.push(line),
    });

    try {
      const sharedTx = `0x${crypto.randomBytes(16).toString("hex")}`;
      const p1 = makeTaskPayload({
        task_id: "gk_canon_1",
        mode: "competition",
        input: { proof_tx: sharedTx },
      });
      const r1 = await postSigned(
        canonicalHandle.url,
        "/gatekeeper/agent",
        JSON.stringify(p1),
        signRaw(JSON.stringify(p1), PRIMARY_SECRET),
      );
      assert.equal(r1.status, 200);
      assert.equal(r1.json.decision, "APPROVE");
      assert.equal(r1.json.reason_code, "VALID_PROOF");
      assert.ok(r1.json.proof && Array.isArray(r1.json.public_signals));

      // Replay maps to PROOF_REPLAY under canonical_rules
      const p2 = makeTaskPayload({
        task_id: "gk_canon_2",
        mode: "competition",
        input: { proof_tx: sharedTx },
      });
      const r2 = await postSigned(
        canonicalHandle.url,
        "/gatekeeper/agent",
        JSON.stringify(p2),
        signRaw(JSON.stringify(p2), PRIMARY_SECRET),
      );
      assert.equal(r2.json.decision, "REJECT");
      assert.equal(r2.json.reason_code, "PROOF_REPLAY");

      // Secret redaction check + positive control
      const combinedLogs = capturedLogs.join("\n");
      assert.equal(
        combinedLogs.includes(syntheticKurierKey),
        false,
        "Kurier API key must never appear in logs",
      );
      assert.equal(
        combinedLogs.includes("[REDACTED_KURIER_KEY]"),
        true,
        "Positive control: scrubbed Kurier path marker must appear in failure log",
      );
    } finally {
      await canonicalHandle.close();
      await new Promise<void>((resolve) => kurierServer.close(() => resolve()));
    }
  });
});
