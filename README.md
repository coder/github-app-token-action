# github-app-token-action

Mints a GitHub App installation token without a private key in GitHub. The App's key lives in
Cloud KMS as a non-exportable HSM key. The job signs in to Google Cloud with its GitHub OIDC
token, has KMS sign the App's JWT, and exchanges the JWT for an installation token limited to
the repositories and permissions you list. The token is revoked when the job ends.

It replaces `actions/create-github-app-token` and its `private-key` secret.

```yaml
jobs:
  release:
    # The Google Cloud provider admits only this environment. Restrict its deployment branches
    # (and add reviewers if the job is not automatic): see "Trust model".
    environment: release
    # An explicit permissions block: the job's GITHUB_TOKEN gets nothing else.
    permissions:
      id-token: write
    steps:
      - id: app
        uses: coder/github-app-token-action@<commit sha> # vX.Y.Z
        with:
          client-id: <App client ID>
          kms-key: projects/<project>/locations/<location>/keyRings/<key ring>/cryptoKeys/<key>
          workload-identity-provider: projects/<project number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
          repositories: coder
          permissions: |
            contents: write
            pull_requests: write
      - run: gh pr list
        env:
          GH_TOKEN: ${{ steps.app.outputs.token }}
          GH_REPO: ${{ github.repository }}
```

## Inputs

| Input | Required | |
|---|---|---|
| `client-id` | yes | The App's client ID (or numeric App ID). |
| `kms-key` | yes | `projects/P/locations/L/keyRings/R/cryptoKeys/K`, optionally with `/cryptoKeyVersions/N`. Without a version, the highest-numbered `ENABLED` RS256 version is used (needs `cloudkms.cryptoKeyVersions.list`). |
| `workload-identity-provider` | yes | `projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` |
| `repositories` | yes | Repository names without the owner, comma- or newline-separated, or `*` for every repository the installation can access. |
| `permissions` | yes | `name: level` per line or comma-separated, with REST API names: `contents: write`, `pull_requests: read`, `organization_administration: write`. |
| `owner` | no | Defaults to the repository owner. Another owner needs `allow-other-owner: true`. |
| `allow-other-owner` | no | `true` to mint a token for an installation on another organization or user. |
| `service-account` | no | Impersonate this service account instead of calling KMS as the federated identity. |
| `skip-token-revoke` | no | `true` keeps the token valid after the job, until it expires (one hour). It still cannot be handed to another job: the runner drops masked values from job outputs. |
| `github-api-url` | no | Defaults to `github.api_url`. Must equal the run's `GITHUB_API_URL` unless `allow-custom-api-url: true`. |
| `allow-custom-api-url` | no | `true` to send the App JWT to a `github-api-url` other than the run's own GitHub API. |

Outputs: `token`, `installation-id`, `app-slug`, `expires-at`.

`repositories` and `permissions` have no defaults on purpose: a token should carry only what its
job needs, rather than everything the installation can do. They limit what the job asks for; they
do not limit what a job with access to the key could ask for (see "Trust model").

## Migrating from `actions/create-github-app-token`

| `create-github-app-token` | here |
|---|---|
| `app-id` / `client-id` | `client-id` |
| `private-key: ${{ secrets.X }}` | `kms-key` and `workload-identity-provider`, plus `permissions: id-token: write` on the job |
| `owner` | `owner` (`allow-other-owner: true` if it is not the repository's owner) |
| `repositories` (optional) | `repositories` (required; `*` for all) |
| `permission-contents: write` | `permissions: contents: write` (required) |

After the switch, delete the App's other private keys in its GitHub settings and delete the
secret that held the old one.

## Trust model

**Signing with the key is holding the App.** Whoever Google Cloud lets use
`roles/cloudkms.signer` on the key can do anything the App can, on every installation of the App:
any `owner`, `repositories: "*"`, every permission the installation has. The inputs only decide
what one job asks for. So:

- Use one App and one key per trust domain (for example one per release process), and install
  each App only where it is needed, with only the permissions it needs.
- Grant the signer role through a Workload Identity provider and binding that admit only the
  repository, environment and ref that should sign. For example, a provider with

  ```text
  assertion.repository_owner_id == "<owner id>" &&
  assertion.repository_id == "<repository id>" &&
  assertion.environment == "release" &&
  assertion.ref == "refs/heads/main" &&
  assertion.job_workflow_ref == "<owner>/<repo>/.github/workflows/release.yml@refs/heads/main"
  ```

  and the signer role granted to
  `principal://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/subject/repo:<owner>/<repo>:environment:release`.
  Match on IDs rather than names (names can be reused after a rename), and include `ref` (or
  `job_workflow_ref` for a reusable workflow): an `environment` alone admits any branch that can
  run in it.
- **The environment is only as strong as its settings.** Restrict its deployment branches or
  tags, and add required reviewers unless the job is meant to run unattended. An environment
  that any branch can use is claimable by anyone who can push a branch or dispatch the workflow.
- **A job with `id-token: write` is as trusted as the key.** Any step in it, not only this
  action, can request an OIDC token for the provider and do the same exchange. Do not give it to
  jobs that run untrusted code: never in `pull_request_target` workflows that check out the pull
  request, and not in jobs that run third-party actions you have not pinned and reviewed.
- **`owner` and `github-api-url` are as sensitive as the key.** The App JWT, which can mint
  tokens for every installation, is sent to `github-api-url`. By default the action only sends it
  to the run's own GitHub API and only mints for the repository's own owner;
  `allow-custom-api-url` and `allow-other-owner` turn those checks off. In a reusable workflow,
  never pass these inputs through from the caller.
- Pin this action by commit SHA. Tags are created only by the security team; `@main` is not
  supported.

What the action itself does:

- Masks the OIDC token, the Google access token, the JWT and the installation token as soon as
  it has each one, and refuses a credential the runner could not mask. Nothing a server sends can
  start a workflow command in the log.
- Refuses an installation that is not this App's or not on `owner`, and a token that grants a
  permission or repository that was not requested. A refused token is revoked.
- Sends the JWT only to `github-api-url` and refuses redirects. Minting is never retried, so a
  lost response cannot leave a token behind.
- Revokes the token in the post step. If anything fails after the token is minted, it is revoked
  right away.

What it trusts besides this repository: the Actions runner (which injects the inputs and the
OIDC request credentials, masks values, and handles outputs and state), the runner's Node 24 and
its CA store, the job's own environment (for example `NODE_OPTIONS` or `NODE_EXTRA_CA_CERTS`,
which earlier steps can set), and GitHub's OIDC endpoint, Google STS, IAM Credentials and Cloud
KMS. `src/` uses only Node built-ins; CI fails if it imports anything else.

## Development

```sh
node --import ./test/guard.mjs --test
```

The `e2e` workflow runs after every push to `main`. It mints a real token with a test App, and
checks that the token reaches only this repository, cannot write, and stops working once the post
step's revocation code has run.
