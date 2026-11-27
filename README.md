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

### Tracing

`hilt serve` exports OpenTelemetry traces over OTLP/HTTP when
`OTEL_EXPORTER_OTLP_ENDPOINT` names a collector; with no endpoint, tracing is
off. A UCAN request is a trace named for the commands it invokes (such as
`/s3/request/authorize`) and a Tenant API request for its route (such as
`GET /tenants/:id`). Each invocation gets its own span, with the Postgres,
OpenBao, PLC directory, Sprue and Swarf calls it makes as child spans. A
caller that sends a `traceparent` header, such as Ingot, gets Hilt's spans in
its own trace. The other standard `OTEL_*` environment variables apply:
`OTEL_EXPORTER_OTLP_HEADERS` authenticates to the collector, and
`OTEL_TRACES_SAMPLER_ARG` sets the fraction of requests traced (`0.01` traces
1%; the default traces every request).

### Storage

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `storage.type` | `--storage` | `HILT_STORAGE_TYPE` | `postgres` |
| `storage.postgres.dsn` | `--postgres-dsn` | `HILT_STORAGE_POSTGRES_DSN` | `postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable` |
| `storage.postgres.max_conns` | _(none)_ | `HILT_STORAGE_POSTGRES_MAX_CONNS` | `10` |
| `storage.postgres.min_conns` | _(none)_ | `HILT_STORAGE_POSTGRES_MIN_CONNS` | `0` |
| `storage.postgres.skip_migrations` | `--skip-migrations` | `HILT_STORAGE_POSTGRES_SKIP_MIGRATIONS` | `false` |

`storage.type` is always `postgres`; any other value is refused at startup.
Migrations run on startup unless `skip_migrations` is set. The same step
creates the task queues' tables (see Task queues), which also needs the
`CREATE` privilege on the database.

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

| Key | Flag | Env var | Example |
| --- | --- | --- | --- |
| `upload.service_id` | `--upload-service-id` | `HILT_UPLOAD_SERVICE_ID` | `did:web:upload.fil-forge.com` |
| `upload.service_url` | `--upload-service-url` | `HILT_UPLOAD_SERVICE_URL` | `https://upload.fil-forge.com` |
| `upload.product_id` | `--upload-product-id` | `HILT_UPLOAD_PRODUCT_ID` | `did:web:hilt.fil-forge.com` |

The Sprue service DID + HTTP endpoint Hilt calls to provision bucket space, and
the product/plan DID tenants are registered under. All three are required, and
`hilt serve` exits at startup when any of them is unset. Each stage points at
its own Sprue.

### Revocation service (Swarf)

| Key | Flag | Env var | Example |
| --- | --- | --- | --- |
| `revocation.service_id` | `--revocation-service-id` | `HILT_REVOCATION_SERVICE_ID` | `did:web:revoke.fil-forge.com` |
| `revocation.service_url` | `--revocation-service-url` | `HILT_REVOCATION_SERVICE_URL` | `https://revoke.fil-forge.com` |

The Swarf service DID + HTTP endpoint Hilt publishes UCAN revocations to when a
delegation it issued is withdrawn (e.g. when an access key is deleted). Both
are required, and `hilt serve` exits at startup when either is unset. Each
stage points at its own Swarf, which only knows that stage's tenants.

### Task queues

| Key | Flag | Env var | Default |
| --- | --- | --- | --- |
| `tasks.tenant_workers` | `--tenant-task-workers` | `HILT_TASKS_TENANT_WORKERS` | `4` |
| `tasks.revocation_workers` | `--revocation-task-workers` | `HILT_TASKS_REVOCATION_WORKERS` | `8` |

Hilt runs durable task queues in its Postgres database, on the libforge task
runner: `queue-tenant` for changes to a tenant's authority and
`queue-revocation` for publishing the revocations a tenant owes to Swarf. A
tenant's status change runs on `queue-tenant`, and the request that makes it
waits for the result. A tenant is `active` (read and write), `write-locked`
(read-only: reads, listings and deletes succeed, and uploads, bucket creation
and configuration changes are refused as `TenantWriteLocked`) or `disabled`
(everything refused as `TenantDisabled`). Every change withdraws the grants
the tenant's access keys hold, queues their revocations, and issues each key
the grants of the new status: all of them for `active`, those of its reads,
listings and deletes for `write-locked`, none for `disabled`. A key created,
or a bucket policy written, for a write-locked tenant gets the narrower
grants too. Creating and deleting an access key run there too. A deletion
withdraws the key's grants and queues their revocations, so the request
returns once the key is gone and Swarf is told moments later. Writing and
removing a bucket policy run there as well: the write gives every affected
principal's keys the grants of the new policy and queues the revocations of
the ones they held. Removing a principal runs there: it strips the principal
from the policies naming it, deletes its keys and queues the revocations of
their grants. Deleting a bucket runs there too: once Sprue reports the bucket
empty it deletes the bucket with its policy and queues the revocations of the
grants over it. With Swarf unreachable these changes still succeed and the
revocations are published once it returns. Deleting a disabled tenant runs
there last of all, and is the one change that needs Swarf up: it publishes
every revocation the tenant owes and those of its keys' grants, deactivates
the tenant's did:plc, and then deletes everything Hilt holds for the tenant.
The request waits for it; a client that disconnects does not stop it, and a
repeated request after it finishes answers `204`. Each
setting is the most queued tasks of that queue one instance runs at once. A
tenant's tasks on a queue always run one at a time, so the count is the number
of tenants worked on together. `0` runs none and leaves the queue to other
instances. The queues' tables live in the `public` schema beside Hilt's own.

A grant lasts 7 days, or until its access key expires if that is sooner.
Hilt issues each key its next grants 3 days before the current ones expire,
checking once an hour, so a key keeps working for as long as it exists. A
grant that is withdrawn is revoked at Swarf, which keeps a revocation only
until the grant it names would have expired.

## Container images

A push to `main` publishes to GHCR from the `Container` workflow. The `prod`
target becomes `ghcr.io/fil-forge/hilt:main`, a stripped binary on a slim Debian
base. The `dev` target becomes `ghcr.io/fil-forge/hilt:main-dev` and adds delve
plus a handful of debugging tools. Both cover `linux/amd64` and `linux/arm64`,
and both also carry a `sha-<short-sha>` tag, the dev image with a `-dev` suffix.

## Deploying to staging

The same run asks [infra-central][] to deploy the prod image to staging. It
dispatches a `bump-deployed-image` event carrying the manifest digest it just
pushed, and infra-central's [Bump deployed image][receiver] workflow opens a
pull request pinning that digest in
`terraform/envs/staging/apps/terraform.tfvars`, with auto-merge enabled.
infra-central's [Check and deploy][deploy] workflow runs `tofu apply` on
`staging/apps` on every push to its `main`, so merging that pull request is
what deploys.

The dispatch runs as the `fil-forge-bot` GitHub App and needs the
`FORGE_BOT_APP_ID` variable and the `FORGE_BOT_PRIVATE_KEY` secret. Prod pins
are promoted by hand: infra-central keeps a pull request open that copies
staging's pins to prod, and a person merges it to promote.

[infra-central]: https://github.com/fil-forge/infra-central
[receiver]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/bump-deployed-image.yml
[deploy]: https://github.com/fil-forge/infra-central/blob/main/.github/workflows/check-and-deploy.yml
