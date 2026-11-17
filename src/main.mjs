import { fail, run } from "./lib.mjs";

run({ env: process.env }).catch(fail);
