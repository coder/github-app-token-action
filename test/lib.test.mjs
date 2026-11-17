import assert from "node:assert/strict";
import { generateKeyPairSync, privateEncrypt, constants, verify } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  InputError,
  command,
  crc32c,
  fail,
  info,
  mask,
  parseApiUrl,
  parseInputs,
  parsePermissions,
  parseRepositories,
  post,
  request,
  resolveKeyVersion,
  run,
} from "../src/lib.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const SHA256_DIGEST_INFO = Buffer.from("3031300d060960864801650304020105000420", "hex");

const KEY = "projects/example-project/locations/global/keyRings/example-ring/cryptoKeys/test-app";
const PROVIDER = "projects/123456/locations/global/workloadIdentityPools/example-pool/providers/example";
const NOW = Date.parse("2026-11-17T12:00:00Z");
const EXPIRES = "2026-11-17T13:00:00Z";
const API = "https://api.github.com";

const OIDC = "github-oidc-token-0123456789";
const FEDERATED = "federated-access-token-0123456789";
const IMPERSONATED = "impersonated-access-token-0123456789";
const TOKEN = "ghs_fakeInstallationToken0123456789";

function readFileCommands(path) {
  const out = {};
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^([^<]+)<<(.+)$/.exec(lines[i]);
    if (!m) continue;
    const value = [];
    for (i++; lines[i] !== m[2]; i++) value.push(lines[i]);
    out[m[1]] = value.join("\n");
  }
  return out;
}

function makeEnv(inputs = {}) {
  const dir = mkdtempSync(join(tmpdir(), "app-token-test-"));
  const env = {
    GITHUB_OUTPUT: join(dir, "output"),
    GITHUB_STATE: join(dir, "state"),
    GITHUB_API_URL: API,
    GITHUB_REPOSITORY_OWNER: "coder",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token?api-version=2.0",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runtime-token",
  };
  writeFileSync(env.GITHUB_OUTPUT, "");
  writeFileSync(env.GITHUB_STATE, "");
  const all = {
    "client-id": "IvTESTCLIENT",
    "kms-key": KEY,
    "workload-identity-provider": PROVIDER,
    owner: "coder",
    repositories: "github-app-token-action",
    permissions: "contents: read\nmetadata: read",
    "github-api-url": API,
    ...inputs,
  };
  for (const [k, v] of Object.entries(all)) env[`INPUT_${k.toUpperCase()}`] = v;
  return env;
}

function json(status, body) {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installation(overrides = {}) {
  return { id: 42, app_slug: "test-app", app_id: 123456, client_id: "IvTESTCLIENT", account: { login: "coder" }, ...overrides };
}

// A fake of GitHub's OIDC endpoint, Google STS/IAM Credentials/KMS and the GitHub API. KMS signs
// the submitted digest with a real RSA key, and GitHub verifies the JWT with its public key.
function fakeServices(overrides = {}, { kmsToken = FEDERATED } = {}) {
  const calls = [];
  const state = {
    versions: [
      { name: `${KEY}/cryptoKeyVersions/2`, state: "ENABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
      { name: `${KEY}/cryptoKeyVersions/10`, state: "ENABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
    ],
  };
  const fetchFn = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    const headers = init.headers ?? {};
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, url, headers, body, init });
    const key = `${method} ${u.origin}${u.pathname}`;
    if (overrides[key]) {
      const res = overrides[key]({ u, headers, body, calls });
      if (res) return res;
    }

    switch (key) {
      case "GET https://oidc.example/token":
        assert.equal(headers.Authorization, "Bearer runtime-token");
        assert.equal(u.searchParams.get("audience"), `https://iam.googleapis.com/${PROVIDER}`);
        return json(200, { value: OIDC });
      case "POST https://sts.googleapis.com/v1/token":
        assert.equal(body.subjectToken, OIDC);
        assert.equal(body.audience, `//iam.googleapis.com/${PROVIDER}`);
        assert.equal(body.subjectTokenType, "urn:ietf:params:oauth:token-type:jwt");
        return json(200, { access_token: FEDERATED, token_type: "Bearer" });
      case `GET https://cloudkms.googleapis.com/v1/${KEY}/cryptoKeyVersions`:
        assert.equal(headers.Authorization, `Bearer ${kmsToken}`);
        assert.equal(u.searchParams.get("filter"), "state=ENABLED");
        return json(200, { cryptoKeyVersions: state.versions });
      case "GET https://api.github.com/orgs/coder/installation":
      case "GET https://api.github.com/users/coder/installation": {
        const jwt = headers.Authorization.replace(/^Bearer /, "");
        const [h, p, s] = jwt.split(".");
        assert.ok(
          verify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url")),
          "JWT signature must verify with the App's public key",
        );
        assert.deepEqual(JSON.parse(Buffer.from(h, "base64url")), { alg: "RS256", typ: "JWT" });
        const claims = JSON.parse(Buffer.from(p, "base64url"));
        assert.deepEqual(claims, { iat: NOW / 1000 - 60, exp: NOW / 1000 + 540, iss: "IvTESTCLIENT" });
        return json(200, installation());
      }
      case "POST https://api.github.com/app/installations/42/access_tokens":
        assert.match(headers.Authorization, /^Bearer /);
        return json(201, {
          token: TOKEN,
          expires_at: EXPIRES,
          permissions: { metadata: "read", ...body.permissions },
          ...(body.repositories
            ? { repository_selection: "selected", repositories: body.repositories.map((name) => ({ name })) }
            : { repository_selection: "all" }),
        });
      case "DELETE https://api.github.com/installation/token":
        assert.equal(headers.Authorization, `token ${TOKEN}`);
        return new Response(null, { status: 204 });
    }
    if (method === "POST" && u.pathname.endsWith(":asymmetricSign")) {
      assert.equal(headers.Authorization, `Bearer ${kmsToken}`);
      const name = decodeURIComponent(u.pathname.slice("/v1/".length, -":asymmetricSign".length));
      const digest = Buffer.from(body.digest.sha256, "base64");
      assert.equal(body.digestCrc32c, String(crc32c(digest)));
      const signature = privateEncrypt(
        { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
        Buffer.concat([SHA256_DIGEST_INFO, digest]),
      );
      return json(200, {
        name,
        signature: signature.toString("base64"),
        verifiedDigestCrc32c: true,
        signatureCrc32c: String(crc32c(signature)),
      });
    }
    throw new Error(`unexpected request: ${key}`);
  };
  const revoked = () => calls.filter((c) => c.method === "DELETE").length;
  return { fetchFn, calls, state, revoked };
}

// Captures what the code writes to stdout (workflow commands and log lines).
async function captureStdout(fn) {
  const lines = [];
  const write = process.stdout.write;
  process.stdout.write = (chunk) => {
    lines.push(...String(chunk).split("\n").filter((l) => l !== ""));
    return true;
  };
  try {
    await fn();
  } finally {
    process.stdout.write = write;
  }
  return lines;
}

const noSleep = { sleep: async () => {} };
const quiet = () => {};
const runWith = (env, svc, extra = {}) =>
  run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep, ...extra });

describe("parseRepositories", () => {
  it("accepts names separated by commas and newlines, without duplicates", () => {
    assert.deepEqual(parseRepositories("a, b\nc\n\na"), ["a", "b", "c"]);
  });
  it('maps "*" to all repositories', () => {
    assert.equal(parseRepositories(" * "), null);
  });
  it("rejects empty input, owner/name and mixing * with names", () => {
    assert.throws(() => parseRepositories(""), InputError);
    assert.throws(() => parseRepositories("coder/coder"), /without the owner/);
    assert.throws(() => parseRepositories("*, coder"), /cannot be combined/);
    assert.throws(() => parseRepositories("bad name"), /invalid name/);
  });
});

describe("parsePermissions", () => {
  it("parses lines and commas", () => {
    assert.deepEqual(parsePermissions("contents: write\npull_requests:read, issues : write"), {
      contents: "write",
      pull_requests: "read",
      issues: "write",
    });
  });
  it("rejects empty input, bad levels, bad names and duplicates", () => {
    assert.throws(() => parsePermissions(" "), /required/);
    assert.throws(() => parsePermissions("contents: none"), /read, write or admin/);
    assert.throws(() => parsePermissions("Contents: read"), /invalid name/);
    assert.throws(() => parsePermissions("contents"), /name: level/);
    assert.throws(() => parsePermissions("contents: read\ncontents: write"), /twice/);
  });
  it("treats names like constructor as plain names", () => {
    assert.deepEqual(parsePermissions("constructor: read"), { constructor: "read" });
  });
});

describe("parseApiUrl", () => {
  it("normalises to origin and path without trailing slashes", () => {
    assert.equal(parseApiUrl("https://api.github.com///"), API);
    assert.equal(parseApiUrl("https://ghes.example/api/v3/"), "https://ghes.example/api/v3");
  });
  it("rejects http, credentials, queries and fragments", () => {
    for (const bad of [
      "http://api.github.com",
      "https://api.github.com@evil.example",
      "https://user:pass@api.github.com",
      "https://api.github.com/?x=1",
      "https://api.github.com/#x",
      "not a url",
    ]) {
      assert.throws(() => parseApiUrl(bad), /https URL without credentials/, bad);
    }
  });
  it("handles a long run of slashes quickly", () => {
    const started = Date.now();
    assert.throws(() => parseApiUrl(`https://a.example${"/".repeat(100_000)}x`));
    assert.equal(parseApiUrl(`https://a.example/x${"/".repeat(2000)}`), "https://a.example/x");
    assert.ok(Date.now() - started < 500);
  });
});

describe("parseInputs", () => {
  it("validates resource names before any request", () => {
    assert.throws(() => parseInputs(makeEnv({ "kms-key": "projects/x/keyRings/y" })), /kms-key/);
    assert.throws(() => parseInputs(makeEnv({ "kms-key": `${KEY}/cryptoKeyVersions/0` })), /kms-key/);
    assert.throws(
      () => parseInputs(makeEnv({ "workload-identity-provider": "projects/p/pools/x" })),
      /workload-identity-provider/,
    );
    assert.throws(() => parseInputs(makeEnv({ "client-id": "abc" })), /client-id/);
    assert.throws(() => parseInputs(makeEnv({ "service-account": "nope" })), /service-account/);
    assert.throws(() => parseInputs(makeEnv({ "github-api-url": "http://x" })), /https/);
    assert.throws(() => parseInputs(makeEnv({ "skip-token-revoke": "yes" })), /true or false/);
  });
  it("accepts a numeric App ID and a pinned version", () => {
    const inputs = parseInputs(makeEnv({ "client-id": "123456", "kms-key": `${KEY}/cryptoKeyVersions/3` }));
    assert.equal(inputs.clientId, "123456");
    assert.equal(inputs.kmsKey, `${KEY}/cryptoKeyVersions/3`);
  });
  it("only sends the JWT to this run's GitHub API unless allowed", () => {
    assert.throws(() => parseInputs(makeEnv({ "github-api-url": "https://evil.example" })), /GITHUB_API_URL/);
    const env = makeEnv();
    delete env.GITHUB_API_URL;
    assert.throws(() => parseInputs(env), /GITHUB_API_URL/);
    const ok = parseInputs(makeEnv({ "github-api-url": "https://ghes.example/api/v3", "allow-custom-api-url": "true" }));
    assert.equal(ok.apiUrl, "https://ghes.example/api/v3");
    assert.equal(parseInputs(makeEnv({ "github-api-url": `${API}/` })).apiUrl, API);
  });
  it("only mints for this repository's owner unless allowed", () => {
    assert.throws(() => parseInputs(makeEnv({ owner: "other-org" })), /allow-other-owner/);
    assert.equal(parseInputs(makeEnv({ owner: "Coder" })).owner, "Coder");
    assert.equal(parseInputs(makeEnv({ owner: "other-org", "allow-other-owner": "true" })).owner, "other-org");
  });
});

describe("workflow commands", () => {
  it("escapes command data, so a message is always one command", async () => {
    const lines = await captureStdout(async () => {
      command("warning", "bad\n::stop-commands::x\r\n%0A");
      const code = process.exitCode;
      fail(new Error("one\n::add-mask::two"));
      process.exitCode = code;
    });
    assert.deepEqual(lines, ["::warning::bad%0A::stop-commands::x%0D%0A%250A", "::error::one%0A::add-mask::two"]);
  });
  it("writes log text as one line", async () => {
    assert.deepEqual(await captureStdout(async () => info("a\n::stop-commands::b\r")), ["a?::stop-commands::b?"]);
  });
  it("refuses to mask a value the runner could not mask, without printing it", async () => {
    const lines = await captureStdout(async () => {
      for (const bad of ["short", "has a space in it 0123", "two\nlines-0123456789", "percent%0A-0123456789", 7]) {
        assert.throws(() => mask("Thing", bad), /Thing: the credential is not in the expected format/);
      }
    });
    assert.deepEqual(lines, []);
  });
});

describe("run", () => {
  it("signs with the newest enabled version and mints a scoped token", async () => {
    const env = makeEnv();
    const svc = fakeServices();
    await runWith(env, svc);

    const sign = svc.calls.find((c) => c.url.endsWith(":asymmetricSign"));
    assert.equal(sign.url, `https://cloudkms.googleapis.com/v1/${KEY}/cryptoKeyVersions/10:asymmetricSign`);

    const create = svc.calls.find((c) => c.url.endsWith("/access_tokens"));
    assert.deepEqual(create.body, {
      permissions: { contents: "read", metadata: "read" },
      repositories: ["github-app-token-action"],
    });

    assert.deepEqual(readFileCommands(env.GITHUB_OUTPUT), {
      token: TOKEN,
      "installation-id": "42",
      "app-slug": "test-app",
      "expires-at": EXPIRES,
    });
    assert.deepEqual(readFileCommands(env.GITHUB_STATE), { token: TOKEN, api_url: API });
    assert.equal(svc.revoked(), 0);
  });

  it("refuses redirects and sets a timeout on every request", async () => {
    const svc = fakeServices();
    await runWith(makeEnv(), svc);
    for (const c of svc.calls) {
      assert.equal(c.init.redirect, "error", c.url);
      assert.ok(c.init.signal instanceof AbortSignal, c.url);
    }
  });

  it("masks every credential before printing anything else, and never prints one", async () => {
    const env = makeEnv();
    const lines = await captureStdout(() =>
      run({ env, fetchFn: fakeServices().fetchFn, now: () => NOW, opts: noSleep }),
    );
    const masks = lines.filter((l) => l.startsWith("::add-mask::")).map((l) => l.slice("::add-mask::".length));
    assert.equal(masks.length, 4);
    assert.deepEqual(masks.slice(0, 2), [OIDC, FEDERATED]);
    assert.match(masks[2], /^[\w-]+\.[\w-]+\.[\w-]+$/); // the JWT
    assert.equal(masks[3], TOKEN);
    const firstLog = lines.findIndex((l) => !l.startsWith("::add-mask::"));
    assert.ok(firstLog > lines.indexOf(`::add-mask::${masks[2]}`), "the JWT is masked before the first log line");
    for (const l of lines.filter((l) => !l.startsWith("::add-mask::"))) {
      for (const secret of masks) assert.ok(!l.includes(secret), l);
    }
  });

  it("calls KMS with a cloudkms-scoped federated token when no service account is given", async () => {
    const svc = fakeServices();
    await runWith(makeEnv(), svc);
    const sts = svc.calls.find((c) => c.url.startsWith("https://sts.googleapis.com/"));
    assert.equal(sts.body.scope, "https://www.googleapis.com/auth/cloudkms");
  });

  it("uses a pinned version without listing, and omits repositories for *", async () => {
    const env = makeEnv({ "kms-key": `${KEY}/cryptoKeyVersions/2`, repositories: "*", permissions: "contents: read" });
    const svc = fakeServices();
    await runWith(env, svc);
    assert.ok(!svc.calls.some((c) => c.url.includes("/cryptoKeyVersions?")));
    assert.ok(svc.calls.some((c) => c.url.endsWith("/cryptoKeyVersions/2:asymmetricSign")));
    const create = svc.calls.find((c) => c.url.endsWith("/access_tokens"));
    assert.deepEqual(create.body, { permissions: { contents: "read" } });
  });

  it("impersonates a service account when one is given", async () => {
    const sa = "app-signer@example-project.iam.gserviceaccount.com";
    const env = makeEnv({ "service-account": sa, "kms-key": `${KEY}/cryptoKeyVersions/2` });
    const svc = fakeServices(
      {
        [`POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa}:generateAccessToken`]: ({
          headers,
          body,
        }) => {
          assert.equal(headers.Authorization, `Bearer ${FEDERATED}`);
          assert.deepEqual(body.scope, ["https://www.googleapis.com/auth/cloudkms"]);
          return json(200, { accessToken: IMPERSONATED });
        },
      },
      { kmsToken: IMPERSONATED },
    );
    await runWith(env, svc);
    assert.ok(svc.calls.some((c) => c.url.includes(":generateAccessToken")));
    const sts = svc.calls.find((c) => c.url.startsWith("https://sts.googleapis.com/"));
    assert.equal(sts.body.scope, "https://www.googleapis.com/auth/cloud-platform");
  });

  it("falls back to a user installation", async () => {
    const svc = fakeServices({
      "GET https://api.github.com/orgs/coder/installation": () => json(404, { message: "Not Found" }),
    });
    await runWith(makeEnv(), svc);
    assert.ok(svc.calls.some((c) => c.url.endsWith("/users/coder/installation")));
  });

  it("fails when the App is not installed", async () => {
    const svc = fakeServices({
      "GET https://api.github.com/orgs/coder/installation": () => json(404, {}),
      "GET https://api.github.com/users/coder/installation": () => json(404, {}),
    });
    await assert.rejects(runWith(makeEnv(), svc), /not installed on coder/);
  });

  it("refuses an installation of another App, on another owner, or with bad fields", async () => {
    for (const [inst, error] of [
      [installation({ client_id: "IvOTHERAPP" }), /belongs to another App/],
      [installation({ account: { login: "someone-else" } }), /not on coder/],
      [installation({ id: "42/../../x" }), /no valid id/],
      [installation({ app_slug: "test-app\n::stop-commands::x" }), /no valid app_slug/],
    ]) {
      const svc = fakeServices({ "GET https://api.github.com/orgs/coder/installation": () => json(200, inst) });
      await assert.rejects(runWith(makeEnv(), svc), error);
      assert.ok(!svc.calls.some((c) => c.url.endsWith("/access_tokens")));
    }
    const numeric = fakeServices({
      "GET https://api.github.com/orgs/coder/installation": () => json(200, installation({ app_id: 999 })),
    });
    await assert.rejects(runWith(makeEnv({ "client-id": "123456" }), numeric), /belongs to another App/);
  });

  for (const [what, grant, error] of [
    ["write instead of read", { permissions: { contents: "write" } }, /granted contents: write/],
    ["an unrequested permission", { permissions: { contents: "read", issues: "read" } }, /granted issues: read/],
    ["metadata: write", { permissions: { contents: "read", metadata: "write" } }, /granted metadata: write/],
    ["every repository", { repository_selection: "all", repositories: undefined }, /not limited/],
    ["another repository", { repositories: [{ name: "github-app-token-action" }, { name: "coder" }] }, /not requested/],
    ["a bad expires_at", { expires_at: "soon" }, /expires_at/],
  ]) {
    it(`revokes and refuses a token with ${what}`, async () => {
      const svc = fakeServices({
        "POST https://api.github.com/app/installations/42/access_tokens": ({ body }) =>
          json(201, {
            token: TOKEN,
            expires_at: EXPIRES,
            permissions: { metadata: "read", ...body.permissions },
            repository_selection: "selected",
            repositories: [{ name: "github-app-token-action" }],
            ...grant,
          }),
      });
      const env = makeEnv();
      await assert.rejects(runWith(env, svc), error);
      assert.equal(svc.revoked(), 1);
      assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"), "");
    });
  }

  it("does not retry minting a token", async () => {
    let mints = 0;
    const svc = fakeServices({
      "POST https://api.github.com/app/installations/42/access_tokens": () => (mints++, json(502, { message: "bad gateway" })),
    });
    await assert.rejects(runWith(makeEnv(), svc), /HTTP 502/);
    assert.equal(mints, 1);
  });

  it("saves state before outputs, and revokes when it cannot write them", async () => {
    const env = makeEnv();
    delete env.GITHUB_OUTPUT;
    const svc = fakeServices();
    await assert.rejects(runWith(env, svc), /file command path/);
    assert.equal(readFileCommands(env.GITHUB_STATE).token, TOKEN);
    assert.equal(svc.revoked(), 1);
  });

  it("reports GitHub's error message", async () => {
    const svc = fakeServices({
      "POST https://api.github.com/app/installations/42/access_tokens": () =>
        json(422, { message: "The permissions requested are not granted to this installation." }),
    });
    await assert.rejects(runWith(makeEnv(), svc), /HTTP 422: The permissions requested are not granted/);
  });

  it("does not quote a response that is not JSON", async () => {
    const svc = fakeServices({
      "POST https://sts.googleapis.com/v1/token": () => new Response(`{"access_token":"${FEDERATED}"`, { status: 200 }),
    });
    const err = await runWith(makeEnv(), svc).catch((e) => e);
    assert.match(err.message, /Google STS token exchange: the response is not JSON/);
    assert.ok(!err.message.includes(FEDERATED));
  });

  it("explains a missing id-token permission", async () => {
    const env = makeEnv();
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
    await assert.rejects(run({ env, fetchFn: fakeServices().fetchFn, log: quiet }), /id-token: write/);
  });

  it("does not save state when revocation is skipped", async () => {
    const env = makeEnv({ "skip-token-revoke": "true" });
    await runWith(env, fakeServices());
    assert.equal(readFileSync(env.GITHUB_STATE, "utf8"), "");
  });
});

describe("KMS", () => {
  it("computes CRC32C", () => {
    assert.equal(crc32c(Buffer.from("123456789")), 0xe3069283);
  });

  it("only uses RS256 versions of the configured key", async () => {
    const svc = fakeServices();
    svc.state.versions = [
      { name: `${KEY}/cryptoKeyVersions/3`, state: "ENABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
      { name: `${KEY}/cryptoKeyVersions/9`, state: "ENABLED", algorithm: "EC_SIGN_P256_SHA256" },
      { name: `${KEY}-other/cryptoKeyVersions/8`, state: "ENABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
      { name: `${KEY}/cryptoKeyVersions/7\n::stop-commands::x`, state: "ENABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
      { name: `${KEY}/cryptoKeyVersions/6`, state: "DISABLED", algorithm: "RSA_SIGN_PKCS1_2048_SHA256" },
    ];
    const version = await resolveKeyVersion({ fetchFn: svc.fetchFn, accessToken: FEDERATED, kmsKey: KEY, opts: noSleep });
    assert.equal(version, `${KEY}/cryptoKeyVersions/3`);

    svc.state.versions = svc.state.versions.slice(1);
    await assert.rejects(
      resolveKeyVersion({ fetchFn: svc.fetchFn, accessToken: FEDERATED, kmsKey: KEY, opts: noSleep }),
      /no ENABLED RS256 versions/,
    );
  });

  for (const [what, change, error] of [
    ["another key version", { name: `${KEY}/cryptoKeyVersions/11` }, /another key version/],
    ["an unverified digest", { verifiedDigestCrc32c: false }, /digest checksum/],
    ["a corrupted signature", { signatureCrc32c: "1" }, /does not match its checksum/],
  ]) {
    it(`refuses a signature from ${what}`, async () => {
      const svc = fakeServices();
      const sign = svc.fetchFn;
      const fetchFn = async (url, init) => {
        const res = await sign(url, init);
        if (!url.endsWith(":asymmetricSign")) return res;
        return json(200, { ...(await res.json()), ...change });
      };
      await assert.rejects(runWith(makeEnv(), { ...svc, fetchFn }), error);
    });
  }
});

describe("request", () => {
  it("retries 5xx and network errors, but not 4xx", async () => {
    let n = 0;
    const flaky = async () => {
      n++;
      if (n === 1) throw new Error("socket hang up");
      if (n === 2) return json(502, { message: "bad gateway" });
      return json(200, {});
    };
    const res = await request(flaky, "x", "https://x", {}, noSleep);
    assert.equal(res.status, 200);
    assert.equal(n, 3);

    let m = 0;
    const res403 = await request(async () => (m++, json(403, {})), "x", "https://x", {}, noSleep);
    assert.equal(res403.status, 403);
    assert.equal(m, 1);
  });

  it("gives up after three attempts", async () => {
    await assert.rejects(request(async () => json(503, { message: "down" }), "KMS", "https://x", {}, noSleep), /KMS: HTTP 503: down/);
  });
});

describe("post", () => {
  const state = { STATE_token: TOKEN, STATE_api_url: API };

  it("revokes the saved token, whatever the local clock says", async () => {
    const svc = fakeServices();
    await post({ env: state, fetchFn: svc.fetchFn, log: quiet, opts: noSleep });
    assert.equal(svc.calls.length, 1);
    assert.equal(svc.calls[0].method, "DELETE");
    assert.equal(svc.calls[0].init.redirect, "error");
  });

  it("skips a missing token", async () => {
    const svc = fakeServices();
    await post({ env: {}, fetchFn: svc.fetchFn, log: quiet });
    assert.equal(svc.calls.length, 0);
  });

  it("accepts 401 (already expired or revoked) and fails on other errors", async () => {
    const respond = (status) => fakeServices({ "DELETE https://api.github.com/installation/token": () => json(status, {}) });
    await post({ env: state, fetchFn: respond(401).fetchFn, log: quiet, opts: noSleep });
    await assert.rejects(post({ env: state, fetchFn: respond(403).fetchFn, log: quiet, opts: noSleep }), /HTTP 403/);
    await assert.rejects(post({ env: state, fetchFn: respond(500).fetchFn, log: quiet, opts: noSleep }), /HTTP 500/);
  });

  it("refuses a saved API URL that is not https", async () => {
    await assert.rejects(
      post({ env: { ...state, STATE_api_url: "http://api.github.com" }, fetchFn: fakeServices().fetchFn, log: quiet }),
      /https URL/,
    );
  });
});
