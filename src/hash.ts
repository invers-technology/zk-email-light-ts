import { createHash } from "crypto";

export const sha256 = (input: string): bigint => {
  const hash = createHash("sha256").update(input).digest("hex");
  return BigInt(`0x${hash}`);
};
