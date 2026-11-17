# github-app-token-action

Mints a GitHub App installation token without a private key in GitHub. The App's key lives in
Cloud KMS as a non-exportable HSM key. The job signs in to Google Cloud with its GitHub OIDC
token, has KMS sign the App's JWT, and exchanges the JWT for an installation token limited to
the repositories and permissions you list. The token is revoked when the job ends.

It replaces `actions/create-github-app-token` and its `private-key` secret.

```yaml
jobs:
  release:
    environment: release # the Google Cloud pool only admits jobs in an environment
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
```

## Inputs

| Input | Required | |
|---|---|---|
| `client-id` | yes | The App's client ID (or numeric App ID). |
| `kms-key` | yes | `projects/P/locations/L/keyRings/R/cryptoKeys/K`, optionally with `/cryptoKeyVersions/N`. Without a version, the highest-numbered `ENABLED` version is used (needs `cloudkms.cryptoKeyVersions.list`). |
| `workload-identity-provider` | yes | `projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` |
| `repositories` | yes | Repository names without the owner, comma- or newline-separated, or `*` for every repository the installation can access. |
| `permissions` | yes | `name: level` per line or comma-separated, with REST API names: `contents: write`, `pull_requests: read`, `organization_administration: write`. |
| `owner` | no | Defaults to the repository owner. |
| `service-account` | no | Impersonate this service account instead of calling KMS as the federated identity. |
| `skip-token-revoke` | no | `true` keeps the token valid after the job (until it expires, after an hour). |
| `github-api-url` | no | Defaults to `github.api_url`. |

Outputs: `token`, `installation-id`, `app-slug`, `expires-at`.

`repositories` and `permissions` have no defaults on purpose: a token should carry only what its
job needs, rather than everything the installation can do.

## Migrating from `actions/create-github-app-token`

| `create-github-app-token` | here |
|---|---|
| `app-id` / `client-id` | `client-id` |
| `private-key: ${{ secrets.X }}` | `kms-key` and `workload-identity-provider`, plus `permissions: id-token: write` on the job |
| `owner` | `owner` |
| `repositories` (optional) | `repositories` (required; `*` for all) |
| `permission-contents: write` | `permissions: contents: write` (required) |

After the switch, delete the App's other private keys in its GitHub settings and delete the
secret that held the old one.

## Security

- No dependencies. `src/` runs as-is on Node 24 and uses only built-ins (fetch and crypto), so
  everything that touches credentials is in this repository.
- The OIDC token, the Google access token, the JWT and the installation token are masked.
- Pin this action by commit SHA.
- Who can sign with which App key is decided in Google Cloud IAM, not here. Grant
  `roles/cloudkms.signer` (and `roles/cloudkms.viewer` to resolve the newest version) on each key
  to the workload identities that need it, as narrowly as possible: repository, environment, and
  ideally workflow file and ref.

## Development

```sh
node --test
```

The `e2e` workflow mints a real token with a test App on every push to `main` and checks that it
only reaches this repository, can't write, and is revoked afterwards.
