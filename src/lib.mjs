// No dependencies on purpose: this code handles credentials that can mint GitHub tokens, so
// everything it runs is in this repository and reviewed here.

import { createHash, randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";

const USER_AGENT = "coder/github-app-token-action";
const GITHUB_API_VERSION = "2022-11-28";

const KMS_KEY_RE =
  /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}(\/cryptoKeyVersions\/[1-9][0-9]*)?$/;
const PROVIDER_RE =
  /^projects\/[0-9]+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]{4,32}\/providers\/[a-z0-9-]{4,32}$/;
const SERVICE_ACCOUNT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;
const CLIENT_ID_RE = /^(Iv[0-9A-Za-z.]{4,40}|[1-9][0-9]{0,15})$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const PERMISSION_NAME_RE = /^[a-z][a-z_]{1,63}$/;
const PERMISSION_LEVELS = new Set(["read", "write", "admin"]);

export class InputError extends Error {}

// --- Inputs -----------------------------------------------------------------------------

export function getInput(env, name) {
  return (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();
}

function splitList(value) {
  return value
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export function parseRepositories(value) {
  const items = splitList(value);
  if (items.length === 0) {
    throw new InputError('repositories is required: list repository names, or "*" for all');
  }
  if (items.includes("*")) {
    if (items.length !== 1) throw new InputError('repositories: "*" cannot be combined with names');
    return null; // all repositories the installation can access
  }
  for (const name of items) {
    if (name.includes("/")) {
      throw new InputError(`repositories: use names without the owner, got "${name}"`);
    }
    if (!REPO_RE.test(name)) throw new InputError(`repositories: invalid name "${name}"`);
  }
  return [...new Set(items)];
}

export function parsePermissions(value) {
  const items = splitList(value);
  if (items.length === 0) {
    throw new InputError('permissions is required, for example "contents: read"');
  }
  const permissions = {};
  for (const item of items) {
    const m = /^([^:\s]+)\s*:\s*(\S+)$/.exec(item);
    if (!m) throw new InputError(`permissions: expected "name: level", got "${item}"`);
    const [, name, level] = m;
    if (!PERMISSION_NAME_RE.test(name)) throw new InputError(`permissions: invalid name "${name}"`);
    if (!PERMISSION_LEVELS.has(level)) {
      throw new InputError(`permissions: level for "${name}" must be read, write or admin`);
    }
    if (name in permissions) throw new InputError(`permissions: "${name}" is listed twice`);
    permissions[name] = level;
  }
  return permissions;
}

export function parseInputs(env) {
  const clientId = getInput(env, "client-id");
  if (!CLIENT_ID_RE.test(clientId)) {
    throw new InputError("client-id must be the App's client ID (Iv...) or numeric App ID");
  }
  const kmsKey = getInput(env, "kms-key");
  if (!KMS_KEY_RE.test(kmsKey)) {
    throw new InputError(
      "kms-key must be projects/P/locations/L/keyRings/R/cryptoKeys/K[/cryptoKeyVersions/N]",
    );
  }
  const provider = getInput(env, "workload-identity-provider");
  if (!PROVIDER_RE.test(provider)) {
    throw new InputError(
      "workload-identity-provider must be projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER",
    );
  }
  const serviceAccount = getInput(env, "service-account");
  if (serviceAccount !== "" && !SERVICE_ACCOUNT_RE.test(serviceAccount)) {
    throw new InputError("service-account must be a service account email");
  }
  const owner = getInput(env, "owner");
  if (!OWNER_RE.test(owner)) throw new InputError("owner must be a GitHub organization or user");
  const apiUrl = getInput(env, "github-api-url").replace(/\/+$/, "");
  if (!/^https:\/\/[^/\s]+(\/[^\s]*)?$/.test(apiUrl)) {
    throw new InputError("github-api-url must be an https URL");
  }
  return {
    clientId,
    kmsKey,
    provider,
    serviceAccount: serviceAccount || null,
    owner,
    repositories: parseRepositories(getInput(env, "repositories")),
    permissions: parsePermissions(getInput(env, "permissions")),
    skipRevoke: parseBoolean(getInput(env, "skip-token-revoke"), "skip-token-revoke"),
    apiUrl,
  };
}

function parseBoolean(value, name) {
  if (value === "" || value === "false") return false;
  if (value === "true") return true;
  throw new InputError(`${name} must be true or false`);
}

// --- Workflow commands ------------------------------------------------------------------

export function mask(value) {
  // Masked values are matched per line; none of ours contain newlines.
  process.stdout.write(`::add-mask::${value}\n`);
}

function writeFileCommand(path, name, value) {
  if (!path) throw new Error("runner file command path is not set");
  const delimiter = `ghadelimiter_${randomUUID()}`;
  appendFileSync(path, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

export function setOutput(env, name, value) {
  writeFileCommand(env.GITHUB_OUTPUT, name, value);
}

export function saveState(env, name, value) {
  writeFileCommand(env.GITHUB_STATE, name, value);
}

// --- HTTP -------------------------------------------------------------------------------

export class HttpError extends Error {
  constructor(what, status, detail) {
    super(`${what}: HTTP ${status}${detail ? `: ${detail}` : ""}`);
    this.status = status;
  }
}

function errorDetail(text) {
  try {
    const body = JSON.parse(text);
    const msg = body.error?.message ?? body.error_description ?? body.message ?? body.error;
    if (typeof msg === "string") return msg.slice(0, 500);
  } catch {}
  return text.slice(0, 200);
}

// Retries network errors and 5xx responses; everything else is returned to the caller.
export async function request(fetchFn, what, url, init, { attempts = 3, sleep = defaultSleep } = {}) {
  let lastError;
  for (let i = 0; i < attempts; i++) {
    if (i > 0) await sleep(1000 * 2 ** (i - 1));
    let res;
    try {
      res = await fetchFn(url, init);
    } catch (err) {
      lastError = new Error(`${what}: ${err.message}`);
      continue;
    }
    if (res.status >= 500) {
      lastError = new HttpError(what, res.status, errorDetail(await res.text()));
      continue;
    }
    return res;
  }
  throw lastError;
}

async function requestJson(fetchFn, what, url, init, opts) {
  const res = await request(fetchFn, what, url, init, opts);
  const text = await res.text();
  if (!res.ok) throw new HttpError(what, res.status, errorDetail(text));
  return text === "" ? {} : JSON.parse(text);
}

function defaultSleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// --- Google Cloud -----------------------------------------------------------------------

export async function getGitHubOidcToken(env, fetchFn, audience, opts) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const token = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !token) {
    throw new InputError('no OIDC token available: the job needs "permissions: id-token: write"');
  }
  const body = await requestJson(
    fetchFn,
    "GitHub OIDC token",
    `${url}&audience=${encodeURIComponent(audience)}`,
    { headers: { Authorization: `Bearer ${token}`, "User-Agent": USER_AGENT } },
    opts,
  );
  if (typeof body.value !== "string") throw new Error("GitHub OIDC token: no value in response");
  return body.value;
}

export async function getGoogleAccessToken({ env, fetchFn, provider, serviceAccount, opts }) {
  const oidc = await getGitHubOidcToken(env, fetchFn, `https://iam.googleapis.com/${provider}`, opts);
  mask(oidc);
  const sts = await requestJson(
    fetchFn,
    "Google STS token exchange",
    "https://sts.googleapis.com/v1/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT },
      body: JSON.stringify({
        grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
        audience: `//iam.googleapis.com/${provider}`,
        scope: "https://www.googleapis.com/auth/cloud-platform",
        requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
        subjectToken: oidc,
        subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
      }),
    },
    opts,
  );
  if (typeof sts.access_token !== "string") throw new Error("Google STS: no access_token in response");
  mask(sts.access_token);
  if (!serviceAccount) return sts.access_token;

  const sa = await requestJson(
    fetchFn,
    `Impersonating ${serviceAccount}`,
    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${serviceAccount}:generateAccessToken`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sts.access_token}`,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify({ scope: ["https://www.googleapis.com/auth/cloudkms"], lifetime: "300s" }),
    },
    opts,
  );
  if (typeof sa.accessToken !== "string") throw new Error("generateAccessToken: no accessToken in response");
  mask(sa.accessToken);
  return sa.accessToken;
}

function versionNumber(name) {
  return Number(name.slice(name.lastIndexOf("/") + 1));
}

export async function resolveKeyVersion({ fetchFn, accessToken, kmsKey, opts }) {
  if (kmsKey.includes("/cryptoKeyVersions/")) return kmsKey;
  const versions = [];
  let pageToken = "";
  do {
    const url = new URL(`https://cloudkms.googleapis.com/v1/${kmsKey}/cryptoKeyVersions`);
    url.searchParams.set("filter", "state=ENABLED");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const body = await requestJson(
      fetchFn,
      `Listing versions of ${kmsKey} (or pin one with /cryptoKeyVersions/N)`,
      url.toString(),
      { headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": USER_AGENT } },
      opts,
    );
    for (const v of body.cryptoKeyVersions ?? []) {
      if (v.state === "ENABLED" && typeof v.name === "string") versions.push(v.name);
    }
    pageToken = body.nextPageToken ?? "";
  } while (pageToken);
  if (versions.length === 0) throw new Error(`${kmsKey} has no ENABLED versions`);
  versions.sort((a, b) => versionNumber(b) - versionNumber(a));
  return versions[0];
}

export async function kmsSign({ fetchFn, accessToken, keyVersion, data, opts }) {
  const digest = createHash("sha256").update(data).digest("base64");
  const body = await requestJson(
    fetchFn,
    `Signing with ${keyVersion}`,
    `https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricSign`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify({ digest: { sha256: digest } }),
    },
    opts,
  );
  if (body.name !== keyVersion) throw new Error(`KMS signed with ${body.name}, expected ${keyVersion}`);
  if (typeof body.signature !== "string") throw new Error("KMS: no signature in response");
  return Buffer.from(body.signature, "base64");
}

// --- GitHub -----------------------------------------------------------------------------

function base64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

// RS256 App JWT. GitHub rejects exp more than 10 minutes ahead, and iat is backdated to allow
// for clock drift.
export async function createAppJwt({ clientId, nowSeconds, sign }) {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 540, iss: clientId }),
  );
  const signingInput = `${header}.${payload}`;
  const signature = await sign(Buffer.from(signingInput));
  return `${signingInput}.${base64url(signature)}`;
}

function githubHeaders(auth) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: auth,
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": GITHUB_API_VERSION,
  };
}

export async function findInstallation({ fetchFn, apiUrl, jwt, owner, opts }) {
  for (const kind of ["orgs", "users"]) {
    const res = await request(
      fetchFn,
      `Finding the installation on ${owner}`,
      `${apiUrl}/${kind}/${owner}/installation`,
      { headers: githubHeaders(`Bearer ${jwt}`) },
      opts,
    );
    const text = await res.text();
    if (res.status === 404) continue;
    if (!res.ok) {
      throw new HttpError(`Finding the installation on ${owner}`, res.status, errorDetail(text));
    }
    return JSON.parse(text);
  }
  throw new Error(`the App is not installed on ${owner}`);
}

export async function createInstallationToken({
  fetchFn,
  apiUrl,
  jwt,
  installationId,
  repositories,
  permissions,
  opts,
}) {
  const body = { permissions };
  if (repositories) body.repositories = repositories;
  const res = await requestJson(
    fetchFn,
    "Creating the installation token",
    `${apiUrl}/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: { ...githubHeaders(`Bearer ${jwt}`), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
    opts,
  );
  if (typeof res.token !== "string") throw new Error("GitHub: no token in response");
  // GitHub never grants more than requested (apart from metadata: read, which every installation
  // token carries), but a token is worth refusing if it did.
  for (const [name, level] of Object.entries(res.permissions ?? {})) {
    if (permissions[name] !== level && !(name === "metadata" && level === "read")) {
      throw new Error(`GitHub granted ${name}: ${level}, which was not requested`);
    }
  }
  return res;
}

export async function revokeInstallationToken({ fetchFn, apiUrl, token, opts }) {
  const res = await request(
    fetchFn,
    "Revoking the installation token",
    `${apiUrl}/installation/token`,
    { method: "DELETE", headers: githubHeaders(`token ${token}`) },
    opts,
  );
  await res.text();
  // 401: already expired or revoked.
  if (res.status !== 204 && res.status !== 401) {
    throw new HttpError("Revoking the installation token", res.status, "");
  }
}

// --- Entry points -----------------------------------------------------------------------

export async function run({ env, fetchFn = fetch, now = () => Date.now(), log = console.log, opts } = {}) {
  const inputs = parseInputs(env);

  const accessToken = await getGoogleAccessToken({
    env,
    fetchFn,
    provider: inputs.provider,
    serviceAccount: inputs.serviceAccount,
    opts,
  });
  const keyVersion = await resolveKeyVersion({ fetchFn, accessToken, kmsKey: inputs.kmsKey, opts });
  log(`Signing the App JWT with ${keyVersion}`);

  const jwt = await createAppJwt({
    clientId: inputs.clientId,
    nowSeconds: Math.floor(now() / 1000),
    sign: (data) => kmsSign({ fetchFn, accessToken, keyVersion, data, opts }),
  });
  mask(jwt);

  const installation = await findInstallation({
    fetchFn,
    apiUrl: inputs.apiUrl,
    jwt,
    owner: inputs.owner,
    opts,
  });
  const created = await createInstallationToken({
    fetchFn,
    apiUrl: inputs.apiUrl,
    jwt,
    installationId: installation.id,
    repositories: inputs.repositories,
    permissions: inputs.permissions,
    opts,
  });
  mask(created.token);

  const scope = inputs.repositories ? inputs.repositories.join(", ") : "all repositories";
  const perms = Object.entries(inputs.permissions)
    .map(([k, v]) => `${k}: ${v}`)
    .join(", ");
  log(
    `Created a token for ${installation.app_slug} on ${inputs.owner} (installation ${installation.id}), ` +
      `expiring ${created.expires_at}. Repositories: ${scope}. Permissions: ${perms}.`,
  );

  setOutput(env, "token", created.token);
  setOutput(env, "installation-id", String(installation.id));
  setOutput(env, "app-slug", installation.app_slug ?? "");
  setOutput(env, "expires-at", created.expires_at ?? "");

  if (!inputs.skipRevoke) {
    saveState(env, "token", created.token);
    saveState(env, "expires_at", created.expires_at ?? "");
    saveState(env, "api_url", inputs.apiUrl);
  }
}

export async function post({ env, fetchFn = fetch, now = () => Date.now(), log = console.log, opts } = {}) {
  const token = env.STATE_token;
  if (!token) {
    log("No token to revoke.");
    return;
  }
  const expiresAt = Date.parse(env.STATE_expires_at ?? "");
  if (!Number.isNaN(expiresAt) && expiresAt <= now()) {
    log("The token has already expired.");
    return;
  }
  await revokeInstallationToken({ fetchFn, apiUrl: env.STATE_api_url, token, opts });
  log("Revoked the installation token.");
}

export function fail(err) {
  const msg = String(err?.message ?? err).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  process.stdout.write(`::error::${msg}\n`);
  process.exitCode = 1;
}
