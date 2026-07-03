# Hilt

Tenant-management service for the Forge network. Hilt owns tenants, their access
keys, and their buckets — plus the UCAN delegations and key material that back
them. It exposes two APIs and talks to one external service:

- **Tenant REST API** (`pkg/api`, echo) — partner-facing CRUD for tenants and
  access keys, guarded by a pre-shared partner key.
- **Hilt UCAN RPC API** (`pkg/rpc`, ucantone server mounted at `POST /`) — the
  `/s3/*` commands Ingot (the S3 gateway) invokes: `/s3/request/authorize`,
  `/s3/bucket/{create,delete,info,list}`.
- **Sprue** (the Forge upload service) — Hilt calls it to provision/inspect a
  bucket's storage space (`pkg/client`).

Module: `github.com/fil-forge/hilt` (Go 1.26). Sibling repos it builds on:
`ucantone` (UCAN primitives: `did`, `multikey`, `ucan/delegation`, `binding`,
`server`, `execution`), `libforge` (bound `commands/*`, `identity`, ucan helpers),
and `sprue` (the upload service; mirror its patterns where relevant).

## Commands

- Build / vet / test: `go build ./... && go vet ./... && go test ./...`. Run all
  three after changes — this is the standard loop.
- Run locally: `go run ./cmd serve` (flags: `--storage=memory --vault=memory` to
  avoid external deps; see `cmd/main.go` / `pkg/config`).
- Postgres and Vault-backed tests use testcontainers and **skip when Docker is
  unavailable** (`internal/testutil`). `go test ./...` passes without Docker but
  only exercises the memory backends; run with Docker for full coverage.
- Editor/LSP diagnostics can lag after cross-file or cross-package edits —
  `go build` / `go vet` are authoritative, prefer them over stale squiggles.

## Layout

- `cmd/main.go` — cobra entrypoint (`serve`).
- `pkg/fx` — uber-fx wiring. `AppModule` picks the storage (`memory`/`postgres`)
  and vault (`memory`/`hashicorp`) backend from config; `ProvideConfigs` splits
  `config.Config` into injectable sub-configs; handlers/services are registered
  here. DI is **by type** — a constructor just declares the deps it needs and the
  provider must exist in the graph.
- `pkg/config` — viper config: file + `HILT_` env prefix (`.`→`_`) + cobra flags.
- `pkg/api` — Tenant REST handlers + the partner-key auth middleware.
- `pkg/rpc` — UCAN S3 command handlers; `pkg/rpc/service/auth` is the shared
  `Authorizer` service.
- `pkg/sigv4` — stdlib-only SigV4 / SigV4a verification, key derivation
  (`DeriveKey`), and local verification (`VerifyWithKey`).
- `pkg/s3perm` — S3-permission → Forge-command mapping (shared by `api` and `rpc`).
- `pkg/store/{tenant,accesskey,bucket,delegation,provider}` — each an interface
  with `memory` and `postgres` backends.
- `pkg/vault` (`memory`, `hashicorp`) — private-key storage; `paths.go` has the
  key path helpers (`TenantKeyPath`, `AccessKeyPath`).
- `pkg/client` — clients for external services (the Sprue `UploadClient`).
- `pkg/migrations` — goose SQL migrations run on startup (unless skipped).
- `internal/testutil` — test-only helpers (random DIDs/issuers, testcontainers).

## Conventions

- **New packages go under `pkg/`**, not `internal/` (only test helpers live in
  `internal/`).
- **Stores**: an interface in `pkg/store/<entity>` with `memory` + `postgres`
  implementations kept in lockstep and exercised by one backend-parametrized test
  suite (`<entity>_test.go`). Add a method to all three (interface + both backends)
  and cover it in that suite.
- **RPC handlers** follow one shape: a `New<Cmd>Handler(logger, deps…) server.Route`
  constructor that returns the libforge bound command's `.Route(...)`, whose closure
  extracts `req.Invocation().Issuer()` / `req.Task().Arguments()` and delegates to an
  **exported, testable** function (`ctx, logger, deps…, issuer, args`). That function
  returns `(*OK, []ucan.Delegation, error)`; the closure calls `res.SetFailure(err)`
  or `res.SetSuccess(ok)`, and attaches any delegation blocks via
  `res.SetMetadata(container.New(container.WithDelegations(blocks...)))` (the result's
  delegation map carries only CIDs — the blocks ride back in the container).
- **Use libforge bound commands** (`.Command`, `.Route`, `.Invoke`, `.Unpack`) — do
  not hand-write command strings with `command.MustParse`.
- **Authorization**: signature-bearing S3 commands authenticate via the
  `auth.Authorizer` service (SigV4/SigV4a verify + time bounds + issuer == tenant's
  provider + region served by that provider). Command-specific S3-permission checks
  stay in each handler. `/s3/bucket/info` is an unauthenticated lookup (no signed
  request).
- **Identities & keys**: tenants are secp256k1 → did:plc; access keys and buckets
  are ed25519 → did:key. Build issuers with `multikey.NewIssuer(did, signer)`. Bucket
  keys are **ephemeral** — used once to sign the bucket→tenant root delegation, then
  discarded (never vaulted). Delegations are issued with `ucan/delegation.Delegate`;
  proof chains come from `delegation.Store.ProofChain`.
- **Terminology**: a UCAN delegation is *issued* (or *re-delegated*), never *minted*.
  Use "issue" in prose, comments, and commit messages.
- **Config**: surface new settings as a sub-config field, wire it through
  `pkg/fx/config.go` `ProvideConfigs`, and add a cobra flag in `cmd/main.go`.
- **fx graph validation**: when a config change alters which modules `AppModule`
  (`pkg/fx/app.go`) wires — a new backend or any config-driven module selection —
  add a case to `pkg/fx/app_test.go` covering each permutation, asserting
  `fx.ValidateApp(appfx.AppModule(cfg), fx.NopLogger)` returns no error (and errors
  for an invalid/unknown selection). This proves every module combination yields a
  graph with all dependencies satisfied, without starting the app.

## Security

Key material is sensitive. **Never log or echo private keys, secrets, or seed
material — log DIDs only.** The vault stores raw key bytes; only DIDs and CIDs
should appear in logs, errors, or test output. Secret-bearing CLI flags (vault
token, AppRole secret, partner key, etc.) warn to prefer `HILT_*` env vars or the
config file over process args; keep that guidance. Use placeholders (never real
values) for keys/tokens in examples and generated config.
