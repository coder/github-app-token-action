// Uses only Node built-ins (no third-party packages), so the code that handles the credentials is
// all in this repository. What else it trusts is listed under "Trust model" in README.md.

import { createHash, randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";

const USER_AGENT = "coder/github-app-token-action";
const GITHUB_API_VERSION = "2022-11-28";

const KMS_KEY_RE =
  /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}(\/cryptoKeyVersions\/[1-9][0-9]{0,9})?$/;
const PROVIDER_RE =
  /^projects\/[0-9]+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]{4,32}\/providers\/[a-z0-9-]{4,32}$/;
const SERVICE_ACCOUNT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/;
const CLIENT_ID_RE = /^(Iv[0-9A-Za-z.]{4,40}|[1-9][0-9]{0,15})$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const PERMISSION_NAME_RE = /^[a-z][a-z_]{1,63}$/;
const PERMISSION_LEVELS = new Set(["read", "write", "admin"]);
const APP_SLUG_RE = /^[A-Za-z0-9-]{1,100}$/;
// RS256 is RSASSA-PKCS1-v1_5 with SHA-256, at any key size.
const SIGNING_ALGORITHM_RE = /^RSA_SIGN_PKCS1_(2048|3072|4096)_SHA256$/;
// Every credential we handle is printable ASCII without spaces or "%", and long enough that
// masking it cannot hide unrelated log text.
const CREDENTIAL_RE = /^[\x21-\x24\x26-\x7e]{16,}$/;
// Characters that would end or break a log line.
const LINE_BREAKING_RE = /[\x00-\x1f\x7f]|\u2028|\u2029/g;
const MAX_KEY_VERSION_PAGES = 50;

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
  const permissions = new Map();
  for (const item of items) {
    const m = /^([^:\s]+)\s*:\s*(\S+)$/.exec(item);
    if (!m) throw new InputError(`permissions: expected "name: level", got "${item}"`);
    const [, name, level] = m;
    if (!PERMISSION_NAME_RE.test(name)) throw new InputError(`permissions: invalid name "${name}"`);
    if (!PERMISSION_LEVELS.has(level)) {
      throw new InputError(`permissions: level for "${name}" must be read, write or admin`);
    }
    if (permissions.has(name)) throw new InputError(`permissions: "${name}" is listed twice`);
    permissions.set(name, level);
  }
  return Object.fromEntries(permissions);
}

// origin + path of an https URL, without a trailing slash. Credentials, a query or a fragment are
// refused rather than dropped, since the App JWT and the token are sent to this URL.
export function parseApiUrl(value, name = "github-api-url") {
  const invalid = () =>
    new InputError(`${name} must be an https URL without credentials, query or fragment`);
  if (value.length > 2048) throw invalid();
  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalid();
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw invalid();
  }
  let path = url.pathname;
  while (path.endsWith("/")) path = path.slice(0, -1);
  return url.origin + path;
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
  if (!parseBoolean(getInput(env, "allow-other-owner"), "allow-other-owner")) {
    const own = env.GITHUB_REPOSITORY_OWNER ?? "";
    if (owner.toLowerCase() !== own.toLowerCase()) {
      throw new InputError(
        `owner "${owner}" is not this repository's owner; set allow-other-owner: true to mint a token for another installation of the App`,
      );
    }
  }

  const apiUrl = parseApiUrl(getInput(env, "github-api-url"));
  if (!parseBoolean(getInput(env, "allow-custom-api-url"), "allow-custom-api-url")) {
    if (!env.GITHUB_API_URL || parseApiUrl(env.GITHUB_API_URL, "GITHUB_API_URL") !== apiUrl) {
      throw new InputError(
        "github-api-url must be this run's GitHub API (GITHUB_API_URL); set allow-custom-api-url: true to send the App JWT elsewhere",
      );
    }
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

// --- Job log and workflow commands ------------------------------------------------------
//
// The runner treats any stdout line that starts with "::" as a command. Everything written here is
// either a command whose data is escaped, or a single line with no control characters, so text
// from a response can never start a line of its own.

function escapeData(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

export function command(name, message) {
  process.stdout.write(`::${name}::${escapeData(message)}\n`);
}

export function info(message) {
  process.stdout.write(`${String(message).replace(LINE_BREAKING_RE, "?")}\n`);
}

// Registers a credential with the runner before anything else can print it. A value the runner
// could not mask as one line is refused instead, and the error never includes it.
export function mask(what, value) {
  if (typeof value !== "string" || !CREDENTIAL_RE.test(value)) {
    throw new Error(`${what}: the credential is not in the expected format`);
  }
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

// The parser's own error quotes the text, which may hold a credential.
function parseJson(what, text) {
  if (text === "") return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what}: the response is not JSON`);
  }
}

// Retries network errors and 5xx responses; everything else is returned to the caller. A request
// that must not run twice passes attempts: 1. Redirects are refused: every endpoint is called by
// its final URL, and a redirect would resend the body (which can hold a credential) elsewhere.
export async function request(
  fetchFn,
  what,
  url,
  init,
  { attempts = 3, sleep = defaultSleep, timeoutMs = 30_000 } = {},
) {
  let lastError;
  for (let i = 0; i < attempts; i++) {
    if (i > 0) await sleep(1000 * 2 ** (i - 1));
    let res;
    try {
      res = await fetchFn(url, { ...init, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
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
  return parseJson(what, text);
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
  mask("GitHub OIDC token", oidc);
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
        // Impersonation needs cloud-platform; calling KMS directly needs only cloudkms.
        scope: serviceAccount
          ? "https://www.googleapis.com/auth/cloud-platform"
          : "https://www.googleapis.com/auth/cloudkms",
        requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
        subjectToken: oidc,
        subjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
      }),
    },
    opts,
  );
  mask("Google STS access token", sts.access_token);
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
  mask("Service account access token", sa.accessToken);
  return sa.accessToken;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function versionNumber(name) {
  return Number(name.slice(name.lastIndexOf("/") + 1));
}

// The newest ENABLED version of the key that signs RS256. Names are checked to be versions of
// this key, since one is logged and then used in the signing URL.
export async function resolveKeyVersion({ fetchFn, accessToken, kmsKey, opts }) {
  if (kmsKey.includes("/cryptoKeyVersions/")) return kmsKey;
  const nameRe = new RegExp(`^${escapeRegExp(kmsKey)}/cryptoKeyVersions/[1-9][0-9]{0,9}$`);
  const versions = [];
  let pageToken = "";
  let pages = 0;
  do {
    if (++pages > MAX_KEY_VERSION_PAGES) throw new Error(`${kmsKey}: too many key versions to list`);
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
    for (const v of Array.isArray(body.cryptoKeyVersions) ? body.cryptoKeyVersions : []) {
      if (
        v?.state === "ENABLED" &&
        typeof v.name === "string" &&
        nameRe.test(v.name) &&
        typeof v.algorithm === "string" &&
        SIGNING_ALGORITHM_RE.test(v.algorithm)
      ) {
        versions.push(v.name);
      }
    }
    pageToken = typeof body.nextPageToken === "string" ? body.nextPageToken : "";
  } while (pageToken);
  if (versions.length === 0) throw new Error(`${kmsKey} has no ENABLED RS256 versions`);
  versions.sort((a, b) => versionNumber(b) - versionNumber(a));
  return versions[0];
}

// CRC32C (Castagnoli), which Cloud KMS uses to check a digest and signature end to end.
const CRC32C_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32c(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC32C_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export async function kmsSign({ fetchFn, accessToken, keyVersion, data, opts }) {
  const digest = createHash("sha256").update(data).digest();
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
      body: JSON.stringify({
        digest: { sha256: digest.toString("base64") },
        digestCrc32c: String(crc32c(digest)),
      }),
    },
    opts,
  );
  if (body.name !== keyVersion) throw new Error(`KMS signed with another key version, expected ${keyVersion}`);
  if (body.verifiedDigestCrc32c !== true) throw new Error("KMS did not verify the digest checksum");
  if (typeof body.signature !== "string") throw new Error("KMS: no signature in response");
  const signature = Buffer.from(body.signature, "base64");
  if (String(crc32c(signature)) !== String(body.signatureCrc32c)) {
    throw new Error("KMS: the signature does not match its checksum");
  }
  return signature;
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

// The installation must be this App's, on the requested owner: its id goes into the minting URL
// and its slug into the log and outputs.
export function checkInstallation(installation, { owner, clientId }) {
  if (!Number.isSafeInteger(installation?.id) || installation.id <= 0) {
    throw new Error("GitHub: the installation has no valid id");
  }
  if (typeof installation.app_slug !== "string" || !APP_SLUG_RE.test(installation.app_slug)) {
    throw new Error("GitHub: the installation has no valid app_slug");
  }
  const login = installation.account?.login;
  if (typeof login !== "string" || login.toLowerCase() !== owner.toLowerCase()) {
    throw new Error(`GitHub: the installation is not on ${owner}`);
  }
  const sameApp = /^[0-9]+$/.test(clientId)
    ? installation.app_id === Number(clientId)
    : installation.client_id === clientId;
  if (!sameApp) throw new Error(`GitHub: the installation on ${owner} belongs to another App`);
  return installation;
}

export async function findInstallation({ fetchFn, apiUrl, jwt, owner, clientId, opts }) {
  const what = `Finding the installation on ${owner}`;
  for (const kind of ["orgs", "users"]) {
    const res = await request(
      fetchFn,
      what,
      `${apiUrl}/${kind}/${owner}/installation`,
      { headers: githubHeaders(`Bearer ${jwt}`) },
      opts,
    );
    const text = await res.text();
    if (res.status === 404) continue;
    if (!res.ok) throw new HttpError(what, res.status, errorDetail(text));
    return checkInstallation(parseJson(what, text), { owner, clientId });
  }
  throw new Error(`the App is not installed on ${owner}`);
}

// The token must not grant more than was asked: no permission that was not requested (every
// installation token also carries metadata: read), and with a repository list, no repository
// outside it.
export function checkGrant(created, { repositories, permissions }) {
  if (typeof created.expires_at !== "string" || Number.isNaN(Date.parse(created.expires_at))) {
    throw new Error("GitHub: the token has no valid expires_at");
  }
  const granted = created.permissions ?? {};
  if (typeof granted !== "object" || Array.isArray(granted)) {
    throw new Error("GitHub: the token's permissions are not an object");
  }
  for (const [name, level] of Object.entries(granted)) {
    const requested = Object.hasOwn(permissions, name) && permissions[name] === level;
    if (!requested && !(name === "metadata" && level === "read")) {
      throw new Error(`GitHub granted ${name}: ${level}, which was not requested`);
    }
  }
  if (repositories) {
    if (created.repository_selection !== "selected" || !Array.isArray(created.repositories)) {
      throw new Error("GitHub: the token is not limited to the requested repositories");
    }
    const allowed = new Set(repositories.map((r) => r.toLowerCase()));
    for (const repo of created.repositories) {
      if (typeof repo?.name !== "string" || !allowed.has(repo.name.toLowerCase())) {
        throw new Error("GitHub: the token reaches a repository that was not requested");
      }
    }
  }
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
  const created = await requestJson(
    fetchFn,
    "Creating the installation token",
    `${apiUrl}/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: { ...githubHeaders(`Bearer ${jwt}`), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
    // Not retried: a response lost after GitHub minted a token would leave one we never see.
    { ...opts, attempts: 1 },
  );
  if (typeof created.token !== "string") throw new Error("GitHub: no token in response");
  try {
    mask("GitHub installation token", created.token);
    checkGrant(created, { repositories, permissions });
  } catch (err) {
    await revokeQuietly({ fetchFn, apiUrl, token: created.token, opts });
    throw err;
  }
  return created;
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

// Used on error paths, where the original error is the one worth reporting.
async function revokeQuietly(args) {
  try {
    await revokeInstallationToken(args);
  } catch {}
}

// --- Entry points -----------------------------------------------------------------------

export async function run({ env, fetchFn = fetch, now = () => Date.now(), log = info, opts } = {}) {
  const inputs = parseInputs(env);

  const accessToken = await getGoogleAccessToken({
    env,
    fetchFn,
    provider: inputs.provider,
    serviceAccount: inputs.serviceAccount,
    opts,
  });
  const keyVersion = await resolveKeyVersion({ fetchFn, accessToken, kmsKey: inputs.kmsKey, opts });

  const jwt = await createAppJwt({
    clientId: inputs.clientId,
    nowSeconds: Math.floor(now() / 1000),
    sign: (data) => kmsSign({ fetchFn, accessToken, keyVersion, data, opts }),
  });
  mask("App JWT", jwt);
  log(`Signed the App JWT with ${keyVersion}`);

  const installation = await findInstallation({
    fetchFn,
    apiUrl: inputs.apiUrl,
    jwt,
    owner: inputs.owner,
    clientId: inputs.clientId,
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

  // From here on, a failure revokes the token rather than leaving it live. State is written first,
  // so that once the token is in an output, the post step can revoke it.
  try {
    if (!inputs.skipRevoke) {
      saveState(env, "token", created.token);
      saveState(env, "api_url", inputs.apiUrl);
    }
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
    setOutput(env, "app-slug", installation.app_slug);
    setOutput(env, "expires-at", created.expires_at);
  } catch (err) {
    await revokeQuietly({ fetchFn, apiUrl: inputs.apiUrl, token: created.token, opts });
    throw err;
  }
}

// Always asks GitHub to revoke: an expired or already revoked token answers 401, which is fine,
// so the runner's clock has no say.
export async function post({ env, fetchFn = fetch, log = info, opts } = {}) {
  const token = env.STATE_token;
  if (!token) {
    log("No token to revoke.");
    return;
  }
  const apiUrl = parseApiUrl(env.STATE_api_url ?? "", "the saved API URL");
  await revokeInstallationToken({
    fetchFn,
    apiUrl,
    token,
    opts: { attempts: 2, timeoutMs: 10_000, ...opts },
  });
  log("Revoked the installation token.");
}

export function fail(err) {
  command("error", err?.message ?? err);
  process.exitCode = 1;
}
