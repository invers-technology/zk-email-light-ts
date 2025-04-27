import { createHash } from "crypto";
import { SHA_PADDED_MESSAGE_LENGTH } from "./input";

export const sha256 = (input: string): string =>
  createHash("sha256").update(input).digest("hex");

// Copy from https://github.com/zkemail/zk-email-verify/tree/main/packages/helpers

// Works only on 32 bit sha text lengths
const int64toBytes = (num: number): Uint8Array => {
  const arr = new ArrayBuffer(8); // an Int32 takes 4 bytes
  const view = new DataView(arr);
  view.setInt32(4, num, false); // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr);
};

const mergeUInt8Arrays = (a1: Uint8Array, a2: Uint8Array): Uint8Array => {
  // sum of individual array lengths
  const mergedArray = new Uint8Array(a1.length + a2.length);
  mergedArray.set(a1);
  mergedArray.set(a2, a1.length);
  return mergedArray;
};

// Works only on 32 bit sha text lengths
const int8toBytes = (num: number): Uint8Array => {
  const arr = new ArrayBuffer(1); // an Int8 takes 4 bytes
  const view = new DataView(arr);
  view.setUint8(0, num); // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr);
};

// Puts an end selector, a bunch of 0s, then the length, then fill the rest with 0s.
export const sha256Pad = (
  message: Uint8Array,
  maxShaBytes: typeof SHA_PADDED_MESSAGE_LENGTH,
): {
  paddedInput: Uint8Array<ArrayBufferLike>;
  paddedInLength: number;
} => {
  const msgLen = message.length * 8; // bytes to bits
  const msgLenBytes = int64toBytes(msgLen);

  let res = mergeUInt8Arrays(message, int8toBytes(2 ** 7)); // Add the 1 on the end, length 505
  // while ((prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !== 0) {
  while ((res.length * 8 + msgLenBytes.length * 8) % 512 !== 0) {
    res = mergeUInt8Arrays(res, int8toBytes(0));
  }

  res = mergeUInt8Arrays(res, msgLenBytes);
  if ((res.length * 8) % 512 !== 0)
    throw new Error("Padding did not complete properly!");
  const messageLen = res.length;
  while (res.length < maxShaBytes) {
    res = mergeUInt8Arrays(res, int64toBytes(0));
  }

  if (res.length !== maxShaBytes)
    throw new Error(
      `Padding to max length did not complete properly! Your padded message is ${res.length} long but max is ${maxShaBytes}!`,
    );

  return {
    paddedInput: res,
    paddedInLength: messageLen,
  };
};
