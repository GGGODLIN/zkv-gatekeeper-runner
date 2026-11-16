import crypto from "node:crypto";

export type HmacSecretFormat = "utf8" | "hex" | "auto";

const HEX_64_RE = /^[0-9a-f]{64}$/i;

function resolveCandidateKeys(
  secret: string,
  format: HmacSecretFormat,
): (string | Buffer)[] {
  if (format === "hex") {
    return HEX_64_RE.test(secret) ? [Buffer.from(secret, "hex")] : [secret];
  }
  if (format === "utf8") {
    return [secret];
  }
  const keys: (string | Buffer)[] = [secret];
  if (HEX_64_RE.test(secret)) {
    keys.push(Buffer.from(secret, "hex"));
  }
  return keys;
}

function normalizeSignatureHeader(
  headerValue: string | string[] | undefined,
): Buffer | null {
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().replace(/^sha256=/i, "");
  if (!HEX_64_RE.test(trimmed)) return null;
  return Buffer.from(trimmed, "hex");
}

export function verifyInboundHmac(
  rawBody: Buffer,
  headerValue: string | string[] | undefined,
  secrets: readonly string[],
  format: HmacSecretFormat = "auto",
): boolean {
  const provided = normalizeSignatureHeader(headerValue);
  if (!provided) return false;

  for (const secret of secrets) {
    if (!secret) continue;
    for (const key of resolveCandidateKeys(secret, format)) {
      const expected = crypto
        .createHmac("sha256", key)
        .update(rawBody)
        .digest();
      if (
        expected.length === provided.length &&
        crypto.timingSafeEqual(expected, provided)
      ) {
        return true;
      }
    }
  }
  return false;
}

export function signOutboundHmac(
  rawBody: Buffer | string,
  secret: string,
  format: "utf8" | "hex" = "utf8",
): string {
  const key =
    format === "hex" && HEX_64_RE.test(secret)
      ? Buffer.from(secret, "hex")
      : secret;
  return crypto.createHmac("sha256", key).update(rawBody).digest("hex");
}
