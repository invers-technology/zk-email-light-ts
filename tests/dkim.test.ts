import fs from "fs";
import { parseEmailToCanonicalized } from "dkim-verifier";

describe("DKIM", () => {
  const emailRaw = fs.readFileSync("tests/dummy/example.eml", "utf8");
  it("should be true", () => {
    const { canonicalizedHeaders, canonicalizedBody, dkim } =
      parseEmailToCanonicalized(emailRaw);

    expect(canonicalizedHeaders).toBeDefined();
    expect(canonicalizedBody).toBeDefined();
    expect(dkim).toBeDefined();
  });
});
