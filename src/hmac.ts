import crypto from "node:crypto";

const HEX_64_RE = /^[0-9a-f]{64}$/i;

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
  secret: string,
): boolean {
  if (!secret) return false;
  const provided = normalizeSignatureHeader(headerValue);
  if (!provided) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest();
  return (
    expected.length === provided.length &&
    crypto.timingSafeEqual(expected, provided)
  );
}

export function signOutboundHmac(
  rawBody: Buffer | string,
  secret: string,
): string {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}
