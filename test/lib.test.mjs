import assert from "node:assert/strict";
import { generateKeyPairSync, privateEncrypt, constants, verify } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  InputError,
  parseInputs,
  parsePermissions,
  parseRepositories,
  post,
  request,
  run,
} from "../src/lib.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const SHA256_DIGEST_INFO = Buffer.from("3031300d060960864801650304020105000420", "hex");

const KEY = "projects/example-project/locations/global/keyRings/example-ring/cryptoKeys/test-app";
const PROVIDER = "projects/123456/locations/global/workloadIdentityPools/example-pool/providers/example";
const NOW = Date.parse("2026-11-17T12:00:00Z");
const EXPIRES = "2026-11-17T13:00:00Z";

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
    "github-api-url": "https://api.github.com",
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

// A fake of GitHub's OIDC endpoint, Google STS/IAM Credentials/KMS and the GitHub API. KMS signs
// the submitted digest with a real RSA key, and GitHub verifies the JWT with its public key.
function fakeServices(overrides = {}, { kmsToken = "federated" } = {}) {
  const calls = [];
  const state = { versions: [`${KEY}/cryptoKeyVersions/2`, `${KEY}/cryptoKeyVersions/10`] };
  const fetchFn = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    const headers = init.headers ?? {};
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, url, headers, body });
    const key = `${method} ${u.origin}${u.pathname}`;
    if (overrides[key]) {
      const res = overrides[key]({ u, headers, body, calls });
      if (res) return res;
    }

    switch (key) {
      case "GET https://oidc.example/token":
        assert.equal(headers.Authorization, "Bearer runtime-token");
        assert.equal(u.searchParams.get("audience"), `https://iam.googleapis.com/${PROVIDER}`);
        return json(200, { value: "github-oidc" });
      case "POST https://sts.googleapis.com/v1/token":
        assert.equal(body.subjectToken, "github-oidc");
        assert.equal(body.audience, `//iam.googleapis.com/${PROVIDER}`);
        assert.equal(body.subjectTokenType, "urn:ietf:params:oauth:token-type:jwt");
        return json(200, { access_token: "federated", token_type: "Bearer" });
      case `GET https://cloudkms.googleapis.com/v1/${KEY}/cryptoKeyVersions`:
        assert.equal(headers.Authorization, `Bearer ${kmsToken}`);
        assert.equal(u.searchParams.get("filter"), "state=ENABLED");
        return json(200, {
          cryptoKeyVersions: state.versions.map((name) => ({ name, state: "ENABLED" })),
        });
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
        return json(200, { id: 42, app_slug: "test-app" });
      }
      case "POST https://api.github.com/app/installations/42/access_tokens":
        assert.match(headers.Authorization, /^Bearer /);
        return json(201, {
          token: "fake-installation-token",
          expires_at: EXPIRES,
          permissions: { metadata: "read", ...body.permissions },
        });
      case "DELETE https://api.github.com/installation/token":
        assert.equal(headers.Authorization, "token fake-installation-token");
        return new Response(null, { status: 204 });
    }
    if (method === "POST" && u.pathname.endsWith(":asymmetricSign")) {
      assert.equal(headers.Authorization, `Bearer ${kmsToken}`);
      const name = decodeURIComponent(u.pathname.slice("/v1/".length, -":asymmetricSign".length));
      const digest = Buffer.from(body.digest.sha256, "base64");
      const signature = privateEncrypt(
        { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
        Buffer.concat([SHA256_DIGEST_INFO, digest]),
      );
      return json(200, { name, signature: signature.toString("base64") });
    }
    throw new Error(`unexpected request: ${key}`);
  };
  return { fetchFn, calls, state };
}

const noSleep = { sleep: async () => {} };
const quiet = () => {};

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
});

describe("run", () => {
  it("signs with the newest enabled version and mints a scoped token", async () => {
    const env = makeEnv();
    const svc = fakeServices();
    await run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep });

    const sign = svc.calls.find((c) => c.url.endsWith(":asymmetricSign"));
    assert.equal(sign.url, `https://cloudkms.googleapis.com/v1/${KEY}/cryptoKeyVersions/10:asymmetricSign`);

    const create = svc.calls.find((c) => c.url.endsWith("/access_tokens"));
    assert.deepEqual(create.body, {
      permissions: { contents: "read", metadata: "read" },
      repositories: ["github-app-token-action"],
    });

    assert.deepEqual(readFileCommands(env.GITHUB_OUTPUT), {
      token: "fake-installation-token",
      "installation-id": "42",
      "app-slug": "test-app",
      "expires-at": EXPIRES,
    });
    assert.deepEqual(readFileCommands(env.GITHUB_STATE), {
      token: "fake-installation-token",
      expires_at: EXPIRES,
      api_url: "https://api.github.com",
    });
  });

  it("uses a pinned version without listing, and omits repositories for *", async () => {
    const env = makeEnv({ "kms-key": `${KEY}/cryptoKeyVersions/2`, repositories: "*", permissions: "contents: read" });
    const svc = fakeServices();
    await run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep });
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
          assert.equal(headers.Authorization, "Bearer federated");
          assert.deepEqual(body.scope, ["https://www.googleapis.com/auth/cloudkms"]);
          return json(200, { accessToken: "impersonated" });
        },
      },
      { kmsToken: "impersonated" },
    );
    await run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep });
    assert.ok(svc.calls.some((c) => c.url.includes(":generateAccessToken")));
  });

  it("falls back to a user installation", async () => {
    const env = makeEnv();
    const svc = fakeServices({
      "GET https://api.github.com/orgs/coder/installation": () => json(404, { message: "Not Found" }),
    });
    await run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep });
    assert.ok(svc.calls.some((c) => c.url.endsWith("/users/coder/installation")));
  });

  it("fails when the App is not installed", async () => {
    const svc = fakeServices({
      "GET https://api.github.com/orgs/coder/installation": () => json(404, {}),
      "GET https://api.github.com/users/coder/installation": () => json(404, {}),
    });
    await assert.rejects(
      run({ env: makeEnv(), fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep }),
      /not installed on coder/,
    );
  });

  it("refuses a token with permissions that were not requested", async () => {
    const svc = fakeServices({
      "POST https://api.github.com/app/installations/42/access_tokens": () =>
        json(201, { token: "fake-installation-token", expires_at: EXPIRES, permissions: { contents: "write" } }),
    });
    const env = makeEnv();
    await assert.rejects(
      run({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep }),
      /granted contents: write/,
    );
    assert.equal(readFileSync(env.GITHUB_OUTPUT, "utf8"), "");
  });

  it("reports GitHub's error message", async () => {
    const svc = fakeServices({
      "POST https://api.github.com/app/installations/42/access_tokens": () =>
        json(422, { message: "The permissions requested are not granted to this installation." }),
    });
    await assert.rejects(
      run({ env: makeEnv(), fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep }),
      /HTTP 422: The permissions requested are not granted/,
    );
  });

  it("explains a missing id-token permission", async () => {
    const env = makeEnv();
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
    await assert.rejects(run({ env, fetchFn: fakeServices().fetchFn, log: quiet }), /id-token: write/);
  });

  it("does not save state when revocation is skipped", async () => {
    const env = makeEnv({ "skip-token-revoke": "true" });
    await run({ env, fetchFn: fakeServices().fetchFn, now: () => NOW, log: quiet, opts: noSleep });
    assert.equal(readFileSync(env.GITHUB_STATE, "utf8"), "");
  });
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
  it("revokes the saved token", async () => {
    const svc = fakeServices();
    const env = { STATE_token: "fake-installation-token", STATE_expires_at: EXPIRES, STATE_api_url: "https://api.github.com" };
    await post({ env, fetchFn: svc.fetchFn, now: () => NOW, log: quiet, opts: noSleep });
    assert.equal(svc.calls.length, 1);
    assert.equal(svc.calls[0].method, "DELETE");
  });
  it("skips missing and expired tokens", async () => {
    const svc = fakeServices();
    await post({ env: {}, fetchFn: svc.fetchFn, log: quiet });
    await post({
      env: { STATE_token: "fake-installation-token", STATE_expires_at: EXPIRES, STATE_api_url: "https://api.github.com" },
      fetchFn: svc.fetchFn,
      now: () => Date.parse(EXPIRES) + 1,
      log: quiet,
    });
    assert.equal(svc.calls.length, 0);
  });
});
