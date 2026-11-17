// The action runs src/ as it is in the repository, on the runner's Node. These checks keep it that
// way: only the Node built-ins in ALLOWED, no way to load code that a review of src/ would miss,
// and action.yml still running src/. CI also runs the tests with test/guard.mjs, which enforces the
// same list on every import that actually happens.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { ALLOWED } from "./import-hooks.mjs";

const SRC = new URL("../src/", import.meta.url);

describe("src/", () => {
  const entries = readdirSync(SRC, { withFileTypes: true });

  it("is only .mjs files, with no subdirectories", () => {
    for (const e of entries) assert.ok(e.isFile() && /^[a-z]+\.mjs$/.test(e.name), e.name);
  });

  for (const { name } of entries) {
    it(`${name} imports only allowed modules, and only statically`, () => {
      const text = readFileSync(new URL(name, SRC), "utf8");
      for (const [pattern, what] of [
        [/\bimport\s*\(/, "a dynamic import()"],
        [/\brequire\s*\(/, "require()"],
        [/\bcreateRequire\b/, "createRequire"],
        [/\bprocess\s*\.\s*(binding|dlopen|_linkedBinding)\b/, "native bindings"],
        [/\beval\s*\(/, "eval()"],
        [/\bnew\s+Function\b/, "new Function"],
        [/\bimport\.meta\.resolve\b/, "import.meta.resolve"],
      ]) {
        assert.doesNotMatch(text, pattern, `${name} uses ${what}`);
      }
      const specifiers = [
        ...text.matchAll(/\b(?:import|export)\b[^;"'`]*?\bfrom\s*(["'])([^"']*)\1/g),
        ...text.matchAll(/\bimport\s*(["'])([^"']*)\1/g),
      ].map((m) => m[2]);
      assert.ok(specifiers.length > 0, `${name} has no imports to check`);
      for (const s of specifiers) {
        assert.ok(ALLOWED.has(s) || /^\.\/[a-z]+\.mjs$/.test(s), `${name} imports "${s}"`);
      }
    });
  }
});

describe("action.yml", () => {
  it("runs src/main.mjs and src/post.mjs on Node 24", () => {
    const text = readFileSync(new URL("../action.yml", import.meta.url), "utf8");
    const runs = /^runs:\n((?: {2}.*\n?)+)/m.exec(text)?.[1] ?? "";
    assert.deepEqual(
      runs.trim().split("\n").map((l) => l.trim()),
      ["using: node24", "main: src/main.mjs", "post: src/post.mjs"],
    );
  });
});
