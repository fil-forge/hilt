# 🗡️ Hilt

Service for managing tenants of Ingot and their secret keys. Hilt implements the Tenant API, provides a UCAN API for retrieving proof chains for invocations into the Forge network and speaks to the Forge upload service.

## Configuration

`hilt serve` is configured from three sources, highest precedence first:
**command-line flag → `HILT_*` environment variable → config file → built-in
default**. The config file is YAML, selected with `-c/--config` (default: a
`config.yaml` in the working directory, then `/etc/hilt/config.yaml`). Every key
has an env var: `HILT_` + the key uppercased with `.` replaced by `_` (e.g.
`storage.postgres.dsn` → `HILT_STORAGE_POSTGRES_DSN`). Config-file keys are the
dotted paths below (nested YAML), e.g. `storage: { postgres: { dsn: ... } }`.

Secrets (partner key, OpenBao token, AppRole secret ID) should be provided via env
var or config file, **not** flags, to avoid exposing them in process args.

### Identity (UCAN RPC service identity)

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `identity.key_file` | `--identity-key-file` | `HILT_IDENTITY_KEY_FILE` | _(ephemeral key)_ |
| `identity.service_id` | `--identity-service-id` | `HILT_IDENTITY_SERVICE_ID` | _(key's did:key)_ |

`key_file` is a PEM-encoded Ed25519 key; when unset an ephemeral key is generated
(its DID changes each restart). `service_id` optionally wraps the key with a
`did:web` (e.g. `did:web:hilt.example.com`).

### Server

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `server.host` | `--host` | `HILT_SERVER_HOST` | `127.0.0.1` |
| `server.port` | `--port` | `HILT_SERVER_PORT` | `8080` |

### Logging

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `log.level` | _(none)_ | `HILT_LOG_LEVEL` | `info` |

### Storage

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `storage.type` | `--storage` | `HILT_STORAGE_TYPE` | `postgres` |
| `storage.postgres.dsn` | `--postgres-dsn` | `HILT_STORAGE_POSTGRES_DSN` | `postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable` |
| `storage.postgres.max_conns` | _(none)_ | `HILT_STORAGE_POSTGRES_MAX_CONNS` | `10` |
| `storage.postgres.min_conns` | _(none)_ | `HILT_STORAGE_POSTGRES_MIN_CONNS` | `0` |
| `storage.postgres.skip_migrations` | `--skip-migrations` | `HILT_STORAGE_POSTGRES_SKIP_MIGRATIONS` | `false` |

`storage.type` is `postgres` or `memory`. Postgres keys apply when
`type=postgres`; migrations run on startup unless `skip_migrations` is set.

### Vault (private-key storage)

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `vault.type` | `--vault` | `HILT_VAULT_TYPE` | `openbao` |
| `vault.openbao.address` | `--openbao-address` | `HILT_VAULT_OPENBAO_ADDRESS` | `http://127.0.0.1:8200` |
| `vault.openbao.mount` | `--openbao-mount` | `HILT_VAULT_OPENBAO_MOUNT` | `secret` |
| `vault.openbao.auth_method` | `--openbao-auth-method` | `HILT_VAULT_OPENBAO_AUTH_METHOD` | `approle` |
| `vault.openbao.token` | `--openbao-token` | `HILT_VAULT_OPENBAO_TOKEN` | _(none)_ — **secret** |
| `vault.openbao.approle.role_id` | `--openbao-approle-role-id` | `HILT_VAULT_OPENBAO_APPROLE_ROLE_ID` | _(none)_ |
| `vault.openbao.approle.secret_id` | `--openbao-approle-secret-id` | `HILT_VAULT_OPENBAO_APPROLE_SECRET_ID` | _(none)_ — **secret** |
| `vault.openbao.approle.mount` | `--openbao-approle-mount` | `HILT_VAULT_OPENBAO_APPROLE_MOUNT` | `approle` |

`vault.type` is `openbao` or `memory`. OpenBao keys apply when
`type=openbao`; `auth_method` is `approle` or `token` (use `token` with
`vault.openbao.token`, or `approle` with the role/secret IDs). With `approle`,
hilt logs in again and retries the operation once when OpenBao rejects its
token (the token infra-central issues lives one hour); with `token`, a rejected
token is a hard error.

### PLC directory

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `plc.directory` | `--plc-directory` | `HILT_PLC_DIRECTORY` | `https://plc.directory` |

### Tenant API auth

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `auth.partner_key` | `--partner-key` | `HILT_AUTH_PARTNER_KEY` | _(none)_ — **secret** |

Pre-shared bearer token required on Tenant API requests.

### Upload service (Sprue)

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `upload.service_id` | `--upload-service-id` | `HILT_UPLOAD_SERVICE_ID` | `did:web:upload.fil-forge.com` |
| `upload.service_url` | `--upload-service-url` | `HILT_UPLOAD_SERVICE_URL` | `https://upload.fil-forge.com` |
| `upload.product_id` | `--upload-product-id` | `HILT_UPLOAD_PRODUCT_ID` | `did:web:hilt.fil-forge.com` |

The Sprue service DID + HTTP endpoint Hilt calls to provision bucket space, and
the product/plan DID tenants are registered under.

### Revocation service (Swarf)

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `revocation.service_id` | `--revocation-service-id` | `HILT_REVOCATION_SERVICE_ID` | `did:web:revoke.fil-forge.com` |
| `revocation.service_url` | `--revocation-service-url` | `HILT_REVOCATION_SERVICE_URL` | `https://revoke.fil-forge.com` |

The Swarf service DID + HTTP endpoint Hilt publishes UCAN revocations to when a
delegation it issued is withdrawn (e.g. when an access key is deleted).

## Container images

A push to `main` publishes to GHCR from the `Container` workflow. The `prod`
target becomes `ghcr.io/fil-forge/hilt:main`, a stripped binary on a slim Debian
base. The `dev` target becomes `ghcr.io/fil-forge/hilt:main-dev` and adds delve
plus a handful of debugging tools. Both cover `linux/amd64` and `linux/arm64`,
and both also carry a `sha-<short-sha>` tag, the dev image with a `-dev` suffix.

## Deploying to dev

The same run asks [infra-central][] to deploy the prod image. It dispatches a
`bump-deployed-image` event carrying the manifest digest it just pushed, and
infra-central's [Bump deployed image][receiver] workflow opens a pull request
pinning that digest in `terraform/envs/dev/apps/terraform.tfvars`, with
auto-merge enabled. infra-central's [Check and deploy][deploy] workflow runs
`tofu apply` on `dev/apps` on every push to its `main`, so merging that pull
request is what deploys.

The dispatch runs as the `fil-forge-bot` GitHub App and needs the
`FORGE_BOT_APP_ID` variable and the `FORGE_BOT_PRIVATE_KEY` secret. Prod pins
are promoted by hand.

[infra-central]: https://github.com/fil-forge/infra-central
[receiver]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/bump-deployed-image.yml
[deploy]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/check-and-deploy.yml
