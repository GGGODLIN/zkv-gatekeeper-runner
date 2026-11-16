import type { Groth16Proof } from "snarkjs";
import { OFFICIAL_GATEKEEPER_VK_HASH } from "./gatekeeper.ts";

export function scrubKurierKey(text: string, apiKey?: string): string {
  let out = text;
  if (apiKey && apiKey.length > 0) {
    out = out.split(apiKey).join("[REDACTED_KURIER_KEY]");
  }
  out = out.replace(
    /\/(submit-proof|job-status|register-vk)\/[^/\s?#]+/g,
    "/$1/[REDACTED_KURIER_KEY]",
  );
  return out;
}

export async function submitToKurier(params: {
  apiKey: string;
  apiUrl?: string;
  proof: Groth16Proof;
  publicSignals: string[];
  timeoutMs: number;
  log: (line: string) => void;
}): Promise<{ jobId: string } | null> {
  const baseUrl = (params.apiUrl ?? "https://api.kurier.xyz/api/v1").replace(
    /\/+$/,
    "",
  );
  const endpoint = `${baseUrl}/submit-proof/${params.apiKey}`;

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          proof: params.proof,
          publicSignals: params.publicSignals,
          vk: OFFICIAL_GATEKEEPER_VK_HASH,
        },
      }),
      signal: AbortSignal.timeout(Math.max(500, params.timeoutMs)),
    });

    if (res.status === 200 || res.status === 202) {
      const body = (await res.json()) as { jobId?: unknown };
      if (typeof body.jobId === "string" && body.jobId.length > 0) {
        return { jobId: body.jobId };
      }
      return null;
    }

    const errText = await res.text().catch(() => "");
    params.log(
      JSON.stringify({
        level: "warn",
        event: "kurier_submit_rejected",
        status: res.status,
        detail: scrubKurierKey(errText.slice(0, 240), params.apiKey),
      }),
    );
    return null;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    params.log(
      JSON.stringify({
        level: "warn",
        event: "kurier_submit_error",
        detail: scrubKurierKey(msg, params.apiKey),
      }),
    );
    return null;
  }
}
