import { z } from "zod";

const EVENT_PAGE_CODES: Record<string, string> = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_PAYLOAD: "PROOF_INVALID",
};

const CANONICAL_RULES_CODES: Record<string, string> = {
  VALID_CONDITION: "VALID_PROOF",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REPLAY",
  EXPIRED_CONDITION: "PUBLIC_INPUT_MISMATCH",
  RECIPIENT_MISMATCH: "PUBLIC_INPUT_MISMATCH",
  AMOUNT_OVERFLOW: "PUBLIC_INPUT_MISMATCH",
  INVALID_PAYLOAD: "PROOF_INVALID",
};

export function resolveReasonCode(
  key: string,
  profile: "event_page" | "canonical_rules",
): string {
  const table =
    profile === "canonical_rules" ? CANONICAL_RULES_CODES : EVENT_PAGE_CODES;
  return table[key] ?? "PROOF_INVALID";
}

const NonNegativeIntInputSchema = z.union([
  z.number().int().nonnegative().refine((n) => Number.isSafeInteger(n), {
    message: "integer must be safe",
  }),
  z
    .string()
    .trim()
    .regex(/^\d+$/, "must be a non-negative integer string"),
]);

export const PreflightEnvelopeSchema = z.object({
  type: z.literal("agent-games.preflight.v1"),
  agent_id: z.string().optional(),
  issued_at: z.string().optional(),
  nonce: z.string().optional(),
});

export const GatekeeperInputSchema = z.object({
  registered_vk: z.string().trim().min(1),
  proof_vk: z.string().trim().min(1),
  minimum: NonNegativeIntInputSchema,
  public_balance: NonNegativeIntInputSchema,
  expiry_block: NonNegativeIntInputSchema,
  current_block: NonNegativeIntInputSchema,
  recipient: z.string().trim().min(1),
  condition_recipient: z.string().trim().min(1),
  amount: NonNegativeIntInputSchema,
  max_transfer: NonNegativeIntInputSchema,
  proof_tx: z.string().trim().min(1),
});

export const GatekeeperTaskEnvelopeSchema = z.object({
  type: z.literal("agent-games.proof-gatekeeper.v1"),
  task_id: z.string().trim().min(1),
  mode: z.enum(["practice", "competition"]),
  issued_at: z.string().optional(),
  deadline_at: z.string().optional(),
  input: GatekeeperInputSchema,
});
