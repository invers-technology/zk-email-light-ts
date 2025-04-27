import fs from "fs";
import path from "path";
import { rsaCircuitInputs } from "../src";
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

  it("should verify dkim signature with rsa circuit", async () => {
    const inputs = await rsaCircuitInputs(emailRaw);
    const circuit = await getCircuit("rsa");
    const witness = await circuit.calculateWitness(inputs);

    await circuit.checkConstraints(witness);
    await circuit.assertOut(witness, {});
  }, 30000);
});
