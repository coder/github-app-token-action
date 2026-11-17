// Loaded with --import by the CI test run, so every module that src/ loads while the tests run
// goes through test/import-hooks.mjs.
import { register } from "node:module";

register("./import-hooks.mjs", import.meta.url);
