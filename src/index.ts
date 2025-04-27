export {
  bigintToCircomInputs,
  CircuitInputBigInt,
  rsaCircuitInputs,
  shaCircuitInputs,
};

import {
  CircuitInputPaddedMessage,
  CircuitInputBigInt,
  bigintToCircomInputs,
} from "./input";
import { rsaCircuitInputs } from "./rsa";
import { shaCircuitInputs } from "./sha";

interface DkimCircuitInputs {
  emailHeader: CircuitInputPaddedMessage;
  emailHeaderLength: number;
  pubkey: CircuitInputBigInt;
  signature: CircuitInputBigInt;
}

export const dkimCircuitInputs = async (
  emailRaw: string,
): Promise<DkimCircuitInputs> => {
  const { modulus: pubkey, signature } = await rsaCircuitInputs(emailRaw);
  const { paddedIn: emailHeader, paddedInLength: emailHeaderLength } =
    shaCircuitInputs(emailRaw);

  return {
    emailHeader,
    emailHeaderLength,
    pubkey,
    signature,
  };
};
