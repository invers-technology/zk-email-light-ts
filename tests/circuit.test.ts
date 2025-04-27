import fs from "fs";
import {
  getDkimPublicKeyN,
  getSignature,
  parseEmailToCanonicalized,
} from "dkim-verifier";
import { bigintToCircomInputs, sha256, CircuitInputBigInt } from "../src";
import path from "path";
const wasm = require("circom_tester").wasm;

describe("Circuit", () => {
  const emailRaw = fs.readFileSync("tests/dummy/example.eml", "utf8");
  const getCircuit = async (name: string) => {
    const circomOption = {
      include: path.join("node_modules"),
    };
    return await wasm(
      path.join(__dirname, "circuits", `${name}.test.circom`),
      circomOption,
    );
  };
  let publicKeyInputs: CircuitInputBigInt,
    signatureInputs: CircuitInputBigInt,
    bodyHashInputs: CircuitInputBigInt;

  it("should generate inputs for rsa circuit", async () => {
    const { canonicalizedHeaders, dkim } = parseEmailToCanonicalized(emailRaw);
    const { n } = await getDkimPublicKeyN(dkim);
    const signature = getSignature(dkim);
    const sha = sha256(canonicalizedHeaders);

    publicKeyInputs = bigintToCircomInputs(n);
    signatureInputs = bigintToCircomInputs(signature);
    bodyHashInputs = bigintToCircomInputs(sha);

    expect(publicKeyInputs).toBeDefined();
    expect(publicKeyInputs.length).toBe(17);
    expect(signatureInputs).toBeDefined();
    expect(signatureInputs.length).toBe(17);
    expect(bodyHashInputs).toBeDefined();
    expect(bodyHashInputs.length).toBe(17);
  });

  it("should verify dkim signature with rsa circuit", async () => {
    const circuit = await getCircuit("rsa");
    const witness = await circuit.calculateWitness({
      modulus: publicKeyInputs,
      signature: signatureInputs,
      message: bodyHashInputs,
    });

    await circuit.checkConstraints(witness);
    await circuit.assertOut(witness, {});
  }, 30000);
});
