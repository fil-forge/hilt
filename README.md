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

Secrets (partner key, Vault token, AppRole secret ID) should be provided via env
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
| `vault.type` | `--vault` | `HILT_VAULT_TYPE` | `hashicorp` |
| `vault.hashicorp.address` | `--hashicorp-address` | `HILT_VAULT_HASHICORP_ADDRESS` | `http://127.0.0.1:8200` |
| `vault.hashicorp.mount` | `--hashicorp-mount` | `HILT_VAULT_HASHICORP_MOUNT` | `secret` |
| `vault.hashicorp.auth_method` | `--hashicorp-auth-method` | `HILT_VAULT_HASHICORP_AUTH_METHOD` | `approle` |
| `vault.hashicorp.token` | `--hashicorp-token` | `HILT_VAULT_HASHICORP_TOKEN` | _(none)_ — **secret** |
| `vault.hashicorp.approle.role_id` | `--hashicorp-approle-role-id` | `HILT_VAULT_HASHICORP_APPROLE_ROLE_ID` | _(none)_ |
| `vault.hashicorp.approle.secret_id` | `--hashicorp-approle-secret-id` | `HILT_VAULT_HASHICORP_APPROLE_SECRET_ID` | _(none)_ — **secret** |
| `vault.hashicorp.approle.mount` | `--hashicorp-approle-mount` | `HILT_VAULT_HASHICORP_APPROLE_MOUNT` | `approle` |

`vault.type` is `hashicorp` or `memory`. HashiCorp keys apply when
`type=hashicorp`; `auth_method` is `approle` or `token` (use `token` with
`vault.hashicorp.token`, or `approle` with the role/secret IDs).

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
| `upload.service_id` | `--upload-service-id` | `HILT_UPLOAD_SERVICE_ID` | `did:web:upload.forgery.network` |
| `upload.service_url` | `--upload-service-url` | `HILT_UPLOAD_SERVICE_URL` | `https://upload.forgery.network` |
| `upload.product_id` | `--upload-product-id` | `HILT_UPLOAD_PRODUCT_ID` | `did:web:hilt.forgery.network` |

The Sprue service DID + HTTP endpoint Hilt calls to provision bucket space, and
the product/plan DID tenants are registered under.
