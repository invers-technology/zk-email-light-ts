import fs from "fs";
import {
  getDkimPublicKeyN,
  getSignature,
  parseEmailToCanonicalized,
} from "dkim-verifier";
import { bigintToCircomInputs } from "../src/input";

describe("Circuit", () => {
  const emailRaw = fs.readFileSync("tests/dummy/example.eml", "utf8");
  it("should be true", async () => {
    const { dkim } = parseEmailToCanonicalized(emailRaw);
    const { n } = await getDkimPublicKeyN(dkim);
    const signature = getSignature(dkim);
    const publicKeyInputs = bigintToCircomInputs(n);
    const signatureInputs = bigintToCircomInputs(signature);

    expect(publicKeyInputs).toBeDefined();
    expect(publicKeyInputs.length).toBe(17);
    expect(signatureInputs).toBeDefined();
    expect(signatureInputs.length).toBe(17);
  });
});
