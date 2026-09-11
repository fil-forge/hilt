# Hilt

Tenant-management service for the Forge network. Hilt owns tenants, their access
keys, and their buckets — plus the UCAN delegations and key material that back
them. It exposes two APIs and talks to one external service:

- **Tenant REST API** (`pkg/api`, echo) — partner-facing CRUD for tenants,
  access keys, principals and bucket policies, guarded by a pre-shared partner
  key. `POST /tenants/{id}/access-keys` creates both key kinds. Without
  `principalId` it is a **service key**: it carries its own `permissions` and
  `buckets`, and the tenant→access-key delegations for them are issued at
  creation. With `principalId` it is a **principal-bound key**: it takes no
  permissions or buckets and holds no delegation — it names a principal (a
  console userId), and what that principal may do on a bucket is computed on
  each authorize from the bucket's policy; the per-request delegations are
  issued by the tenant at that moment.
- **Hilt UCAN RPC API** (`pkg/rpc`, ucantone server mounted at `POST /`) — the
  `/s3/*` commands Ingot (the S3 gateway) invokes: `/s3/request/authorize`,
  `/s3/bucket/{create,delete,info,list}`; and the self-issued admin commands
  `/admin/provider/{add,list}` and `/admin/provider/nodes/set` (`hilt client admin`).
- **Sprue** (the Forge upload service) — Hilt calls it to provision/inspect a
  bucket's storage space and to manage routing policies (`pkg/client`): each
  provider owns a policy whose candidates are its storage nodes, and every
  bucket's space is pointed at its provider's policy on creation.

Module: `github.com/fil-forge/hilt` (Go 1.27). Sibling repos it builds on:
`ucantone` (UCAN primitives: `did`, `multikey`, `ucan/delegation`, `binding`,
`server`, `execution`), `libforge` (bound `commands/*`, `identity`, ucan helpers),
and `sprue` (the upload service; mirror its patterns where relevant).

## Commands

- Build / vet / test: `go build ./... && go vet ./... && go test ./...`. Run all
  three after changes — this is the standard loop.
- Run locally: `go run ./cmd serve` (flags: `--storage=memory --vault=memory` to
  avoid external deps; see `cmd/main.go` / `pkg/config`).
- Postgres and OpenBao-backed tests use testcontainers and **skip when Docker is
  unavailable** (`internal/testutil`). `go test ./...` passes without Docker but
  only exercises the memory backends; run with Docker for full coverage.
- Integration tests: `make itest`. The `itest/` package is gated by the `itest`
  build tag, so `go test ./...` never compiles or runs it. It boots the full
  Forge stack in Docker via `smelt/pkg/stack` (the working tree's hilt is
  compiled as a static linux binary and mounted over the published
  `ghcr.io/fil-forge/hilt:main` image) and tests against real ingot, sprue,
  piri, plc, and swarf. ~5-10 min; needs Docker; **one itest run per Docker
  host at a time** (TestMain's `CleanupLeaked` sweeps every `smeltery-*`
  compose project, including another run's live containers). Vet it with
  `go vet -tags itest ./itest`. Peer services are pulled as mutable `:main`
  images Docker never re-pulls — `docker pull` them when the stack misbehaves,
  or override per run with `HILT_ITEST_UPLOAD_IMAGE` / `HILT_ITEST_PIRI_IMAGE`
  / `HILT_ITEST_INGOT_IMAGE` / `HILT_ITEST_SWARF_IMAGE` / `HILT_ITEST_PIRI_BINARY`
  / `HILT_ITEST_SWARF_BINARY` / `HILT_ITEST_INGOT_BINARY`. A binary override
  wants a static linux build for the Docker host's architecture
  (`GOOS=linux GOARCH=<host arch> CGO_ENABLED=0 GOWORK=off go build`), and is
  how the IAM scenarios run against swarf and ingot changes the `:main` images
  do not carry yet. The suite also mounts a swarf config naming this stack's
  hilt (`did:web:hilt`) as a principal-invalidation publisher, because smelt's
  swarf definition configures no publisher list and swarf refuses every
  invalidation without one. Until the published `:main` images carry the
  swarf and ingot IAM changes, the IAM scenarios skip unless both binary
  overrides are set (or `HILT_ITEST_IAM=1`); drop that guard once they do.
  CI runs the suite after the unit job, on every push.
- Editor/LSP diagnostics can lag after cross-file or cross-package edits —
  `go build` / `go vet` are authoritative, prefer them over stale squiggles.

## Layout

- `cmd/main.go` — cobra entrypoint (`serve`).
- `pkg/fx` — uber-fx wiring. `AppModule` picks the storage (`memory`/`postgres`)
  and vault (`memory`/`openbao`) backend from config; `ProvideConfigs` splits
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
- `pkg/bucketpolicy` — the bucket policy and its evaluation: `Validate`,
  `Canonical`/`ETag` (compare-and-set), `Effective(doc, principal)` (Deny beats
  Allow), and `Changed(old, new, …)`, which names the principals a write
  invalidates. Pure: no store or transport dependencies.
- `pkg/invalidation` — publishes principal invalidations to Swarf, signed as
  Hilt's own service identity. A principal holds no delegation, so a revocation
  cannot name what a gateway must drop. `Timeout` bounds one publish and
  `BatchTimeout` a write's whole fan-out, both below `store.LockTimeout`.
- `pkg/store/{tenant,accesskey,bucket,delegation,provider,principal,bucketpolicy}` —
  each an interface with `memory` and `postgres` backends.
- `pkg/store/pglock` — the Postgres locking helpers the stores share:
  `SetTimeout` (SET LOCAL lock_timeout) and `MapError` (lock_not_available →
  `store.ErrLockTimeout`).
- `pkg/vault` (`memory`, `openbao`) — private-key storage; `paths.go` has the
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
- **Locking and callbacks**: a write that another service must learn about runs
  in one transaction — lock the row (`SELECT … FOR UPDATE`), run the
  caller-supplied `beforeCommit` callback, commit. The callback publishes the
  principal invalidation, so a failed publish rolls the write back and leaves
  the principal with its old access, never with more. Memory backends run the
  callback under the store mutex. A reader that must not be answered from a
  snapshot older than an in-flight write passes
  `store.WithLock(store.LockShare)` (`SELECT … FOR SHARE`; a no-op for memory,
  which already serializes). Every lock is bounded by `store.LockTimeout` —
  callbacks open further transactions, so two writes can wait on each other
  through an edge Postgres cannot see — and a statement that gives up returns
  `store.ErrLockTimeout`.
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
  provider + region served by that provider), which also classifies the operation
  and resolves every bucket it addresses within the tenant and the key's scope. A
  copy (`x-amz-copy-source` on a PUT) is two decisions: the write on the
  destination and `s3:GetObject` on the source, and the header must be a signed
  header. Command-specific S3-permission checks stay in each handler.
  `/s3/bucket/info` is an unauthenticated lookup (no signed request).
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
