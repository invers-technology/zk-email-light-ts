# [ZkEmail](https://github.com/zkemail) Light Client with Typescript

[![MIT License](https://img.shields.io/github/license/invers-technology/zk-email-light-ts?style=flat-square)](https://github.com/invers-technology/zk-email-light-ts/blob/master/LICENSE) [![Language](https://img.shields.io/badge/language-TypeScript-blue.svg?style=flat-square)](https://www.typescriptlang.org) ![npm version](https://badge.fury.io/js/zk-email-light.svg)

[ZkEmail](https://github.com/zkemail) verifier only for Dkim headers.

**Use at your own risk**.

## Install

```
$ npm i zk-email-light
```

## Usage

```ts
import fs from "fs";
import path from "path";
import { rsaCircuitInputs } from "zk-email-light";

const emailRaw = fs.readFileSync("tests/dummy/example.eml", "utf8");
const inputs = await rsaCircuitInputs(emailRaw);
const circuit = await getCircuit("rsa");
const witness = await circuit.calculateWitness(inputs);

await circuit.checkConstraints(witness);
await circuit.assertOut(witness, {});
```
