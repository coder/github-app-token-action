// Module resolve hook, registered by test/guard.mjs for the whole test run: a module in src/ may
// only import the Node built-ins in ALLOWED and other .mjs files directly in src/. Anything else
// fails the import, and with it the tests.

const SRC = new URL("../src/", import.meta.url).href;
export const ALLOWED = new Set(["node:crypto", "node:fs"]);

export async function resolve(specifier, context, nextResolve) {
  const result = await nextResolve(specifier, context);
  if (context.parentURL?.startsWith(SRC)) {
    const inSrc = result.url.startsWith(SRC) && /^[a-z]+\.mjs$/.test(result.url.slice(SRC.length));
    if (!ALLOWED.has(result.url) && !inSrc) {
      throw new Error(`src/ may only import ${[...ALLOWED].join(", ")} and its own files, not "${specifier}"`);
    }
  }
  return result;
}
