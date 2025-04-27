import {
  parseEmailToCanonicalized,
  getDkimPublicKeyN,
  getSignature,
} from "dkim-verifier";
import {
  bigintToCircomInputs,
  CircuitInputBigInt,
  CircuitInputPaddedMessage,
  SHA_PADDED_MESSAGE_LENGTH,
} from "./input";
import { sha256, sha256Pad } from "./hash";

interface RsaCircuitInputs {
  modulus: CircuitInputBigInt;
  signature: CircuitInputBigInt;
  message: CircuitInputBigInt;
}

export interface ShaCircuitInputs {
  paddedIn: CircuitInputPaddedMessage;
  paddedInLength: number;
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

export const shaCircuitInputs = (emailRaw: string): ShaCircuitInputs => {
  const { canonicalizedHeaders } = parseEmailToCanonicalized(emailRaw);
  const bufferMessage = Buffer.from(canonicalizedHeaders, "ascii");
  const { paddedInput, paddedInLength } = sha256Pad(
    bufferMessage,
    SHA_PADDED_MESSAGE_LENGTH,
  );

  return {
    paddedIn: Array.from(paddedInput).map(Number) as CircuitInputPaddedMessage,
    paddedInLength,
  };
};
