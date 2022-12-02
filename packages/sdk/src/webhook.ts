import crypto from "crypto";

/**
 * Verifies the integrity and authenticity of the data payload.
 *
 * @param secret shared signature key
 * @param dataPayload JSON body of request
 * @param timestamp signature timestamp in request header
 * @param signature signature in request header
 * @returns true if signatures match, false otherwise
 */
export function verify(
  secret: string,
  dataPayload: Record<string, string>,
  timestamp: string,
  signature: string
): boolean {
  const verification = sign(secret, JSON.stringify({ ...dataPayload, timestamp }));
  return crypto.timingSafeEqual(Buffer.from(verification), Buffer.from(signature));
}

/**
 * Produces a signature for a given string using the provided secret key.
 *
 * @param secret shared signature key
 * @param data string to sign
 * @returns signature on data using signature key
 */
export function sign(secret: string, data: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}
