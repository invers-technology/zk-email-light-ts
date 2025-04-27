import { FixedLengthArray } from "./array";

// circom rsa field expression
// 121 bits * 17 = 2057 bits operation
const RSA_FIELD_BITS = 121;
const RSA_FIELD_LENGTH = 17;
const BIGINT_121_MAX = 2n ** BigInt(RSA_FIELD_BITS) - 1n;

export type CircuitInputBigInt = FixedLengthArray<bigint, 17>;

export const bigintToCircomInputs = (n: bigint): CircuitInputBigInt => {
  return Array.from({ length: Number(RSA_FIELD_LENGTH) }, (_, i) => {
    const remainder = n >> BigInt(i * RSA_FIELD_BITS);
    return remainder & BIGINT_121_MAX;
  }) as CircuitInputBigInt;
};

export const SHA_PADDED_MESSAGE_LENGTH = 640;
export type CircuitInputPaddedMessage = FixedLengthArray<number, 640>;
