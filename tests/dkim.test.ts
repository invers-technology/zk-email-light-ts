import fs from "fs";
import {
  parseEmailToCanonicalized,
  verifyBody,
  verifyDkimSignature,
  getDkimPublicKey,
} from "dkim-verifier";

describe("DKIM", () => {
  const emailRaw = fs.readFileSync("tests/dummy/example.eml", "utf8");
  it("should be true", async () => {
    const { canonicalizedHeaders, canonicalizedBody, dkim } =
      parseEmailToCanonicalized(emailRaw);
    const isBodyVerified = verifyBody(canonicalizedBody, dkim);
    const publicKey = await getDkimPublicKey(dkim);
    const isDkimVerified = verifyDkimSignature(
      dkim,
      canonicalizedHeaders,
      publicKey,
    );

    expect(isDkimVerified).toBe(true);
    expect(isBodyVerified).toBe(true);
  });
});
