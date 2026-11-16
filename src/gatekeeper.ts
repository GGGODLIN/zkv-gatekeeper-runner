import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import type { z } from "zod";
import type { GatekeeperTaskEnvelopeSchema } from "./types.ts";

const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const MAX_BLOCK_NUMBER = (1n << 32n) - 1n;
const MAX_UINT64 = (1n << 64n) - 1n;

function toFieldElement(raw: string): string {
  const trimmed = raw.trim();
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed) || /^\d+$/.test(trimmed)) {
    return (BigInt(trimmed) % BN254_R).toString(10);
  }
  const digestHex = crypto.createHash("sha256").update(trimmed).digest("hex");
  return (BigInt(`0x${digestHex}`) % BN254_R).toString(10);
}

function parseUnsignedBigInt(value: string | number): bigint {
  return typeof value === "number" ? BigInt(value) : BigInt(value.trim());
}

export function evaluateGatekeeperRules(
  task: z.infer<typeof GatekeeperTaskEnvelopeSchema>,
  nowMs: number = Date.now(),
): {
  decision: "APPROVE" | "REJECT";
  reasonKey: string;
  circuitProvable: boolean;
  normalized: {
    registeredVk: string;
    proofVk: string;
    minimum: bigint;
    publicBalance: bigint;
    expiryBlock: bigint;
    currentBlock: bigint;
    recipient: string;
    conditionRecipient: string;
    amount: bigint;
    maxTransfer: bigint;
  };
} {
  const input = task.input;
  const registeredVk = input.registered_vk.trim().toLowerCase();
  const proofVk = input.proof_vk.trim().toLowerCase();
  const recipient = input.recipient.trim().toLowerCase();
  const conditionRecipient = input.condition_recipient.trim().toLowerCase();

  const minimum = parseUnsignedBigInt(input.minimum);
  const publicBalance = parseUnsignedBigInt(input.public_balance);
  const expiryBlock = parseUnsignedBigInt(input.expiry_block);
  const currentBlock = parseUnsignedBigInt(input.current_block);
  const amount = parseUnsignedBigInt(input.amount);
  const maxTransfer = parseUnsignedBigInt(input.max_transfer);

  const normalized = {
    registeredVk,
    proofVk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient,
    conditionRecipient,
    amount,
    maxTransfer,
  };

  if (task.deadline_at !== undefined) {
    const parsedDeadline = Date.parse(task.deadline_at);
    if (!Number.isFinite(parsedDeadline)) {
      return {
        decision: "REJECT",
        reasonKey: "INVALID_PAYLOAD",
        circuitProvable: false,
        normalized,
      };
    }
    if (parsedDeadline <= nowMs) {
      return {
        decision: "REJECT",
        reasonKey: "EXPIRED_CONDITION",
        circuitProvable: false,
        normalized,
      };
    }
  }

  // Enforce gatekeeper.wasm comparator domain bounds before witness generation
  if (
    expiryBlock > MAX_BLOCK_NUMBER ||
    currentBlock > MAX_BLOCK_NUMBER ||
    minimum > MAX_UINT64 ||
    publicBalance > MAX_UINT64
  ) {
    return {
      decision: "REJECT",
      reasonKey: "INVALID_PAYLOAD",
      circuitProvable: false,
      normalized,
    };
  }

  const vkFieldCollision =
    registeredVk !== proofVk &&
    toFieldElement(registeredVk) === toFieldElement(proofVk);
  const recipientFieldCollision =
    recipient !== conditionRecipient &&
    toFieldElement(recipient) === toFieldElement(conditionRecipient);

  if (vkFieldCollision || recipientFieldCollision) {
    return {
      decision: "REJECT",
      reasonKey: vkFieldCollision ? "VK_SUBSTITUTION" : "RECIPIENT_MISMATCH",
      circuitProvable: false,
      normalized,
    };
  }

  if (registeredVk !== proofVk) {
    return {
      decision: "REJECT",
      reasonKey: "VK_SUBSTITUTION",
      circuitProvable: true,
      normalized,
    };
  }

  if (publicBalance < minimum) {
    return {
      decision: "REJECT",
      reasonKey: "THRESHOLD_MISMATCH",
      circuitProvable: true,
      normalized,
    };
  }

  // gatekeeper.wasm enforces strict currentBlock < expiryBlock for decision=1
  if (currentBlock >= expiryBlock) {
    return {
      decision: "REJECT",
      reasonKey: "EXPIRED_CONDITION",
      circuitProvable: true,
      normalized,
    };
  }

  if (recipient !== conditionRecipient) {
    return {
      decision: "REJECT",
      reasonKey: "RECIPIENT_MISMATCH",
      circuitProvable: true,
      normalized,
    };
  }

  if (amount > maxTransfer) {
    return {
      decision: "REJECT",
      reasonKey: "AMOUNT_OVERFLOW",
      circuitProvable: true,
      normalized,
    };
  }

  return {
    decision: "APPROVE",
    reasonKey: "VALID_CONDITION",
    circuitProvable: true,
    normalized,
  };
}

export async function proveGatekeeperDecision(params: {
  taskId: string;
  evaluation: ReturnType<typeof evaluateGatekeeperRules>;
  wasmPath: string;
  zkeyPath: string;
  vk: Record<string, unknown>;
  timeoutMs: number;
}): Promise<{ proof: Record<string, unknown>; publicSignals: string[] } | null> {
  const { evaluation } = params;
  if (!evaluation.circuitProvable) return null;

  const saltBigInt =
    BigInt(`0x${crypto.randomBytes(31).toString("hex")}`) % BN254_R;

  const circuitInput: Record<string, string> = {
    registeredVkHash: toFieldElement(evaluation.normalized.registeredVk),
    proofVkHash: toFieldElement(evaluation.normalized.proofVk),
    minimum: evaluation.normalized.minimum.toString(10),
    publicBalance: evaluation.normalized.publicBalance.toString(10),
    expiryBlock: evaluation.normalized.expiryBlock.toString(10),
    currentBlock: evaluation.normalized.currentBlock.toString(10),
    recipient: toFieldElement(evaluation.normalized.recipient),
    conditionRecipient: toFieldElement(evaluation.normalized.conditionRecipient),
    amount: evaluation.normalized.amount.toString(10),
    maxTransfer: evaluation.normalized.maxTransfer.toString(10),
    decision: evaluation.decision === "APPROVE" ? "1" : "0",
    taskId: toFieldElement(params.taskId),
    salt: saltBigInt.toString(10),
  };

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error("Gatekeeper proving soft deadline exceeded")),
      params.timeoutMs,
    );
  });

  try {
    const result = (await Promise.race([
      snarkjs.groth16.fullProve(circuitInput, params.wasmPath, params.zkeyPath),
      timeoutPromise,
    ])) as { proof: Record<string, unknown>; publicSignals: string[] };
    const valid = await snarkjs.groth16.verify(
      params.vk,
      result.publicSignals,
      result.proof,
    );
    if (!valid) {
      return null;
    }
    return result;
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}
