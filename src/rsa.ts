import {
  parseEmailToCanonicalized,
  getDkimPublicKeyN,
  getSignature,
} from "dkim-verifier";
import { bigintToCircomInputs, CircuitInputBigInt } from "./input";
import { sha256 } from "./sha";

interface RsaCircuitInputs {
  modulus: CircuitInputBigInt;
  signature: CircuitInputBigInt;
  message: CircuitInputBigInt;
}

export const rsaCircuitInputs = async (
  emailRaw: string,
): Promise<RsaCircuitInputs> => {
  const { canonicalizedHeaders, dkim } = parseEmailToCanonicalized(emailRaw);
  const { n } = await getDkimPublicKeyN(dkim);
  const signature = getSignature(dkim);
  const sha = sha256(canonicalizedHeaders);
  const shaBigint = BigInt(`0x${sha}`);

  return {
    modulus: bigintToCircomInputs(n),
    signature: bigintToCircomInputs(signature),
    message: bigintToCircomInputs(shaBigint),
  };
};
