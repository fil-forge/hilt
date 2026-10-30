# Hilt

Tenant-management service for the Forge network. Hilt owns tenants, their access
keys, and their buckets — plus the UCAN delegations and key material that back
them. It exposes two APIs and talks to three external services:

- **Tenant REST API** (`pkg/api`, echo) — partner-facing CRUD for tenants,
  access keys and principals, guarded by a pre-shared partner
  key. `POST /tenants/{id}/access-keys` creates both key kinds. Without
  `principalId` it is a **service key**: it carries its own `permissions` and
  `buckets`, and the tenant→access-key delegations for them are issued at
  creation. With `principalId` it is a **principal-bound key**: it takes no
  permissions or buckets (both stored as `NULL`) and names a principal (the
  console's `principalId`). What that principal may do on a bucket is the
  bucket policy's effective set for it, and the key holds, over each bucket
  the principal can reach, the tenant→access-key delegations for the Forge
  commands that set maps to (`pkg/grant`), rewritten on every policy change.
  Each authorize evaluates the policy and re-delegates from the key to the
  gateway, as a service key does. Removing a principal tombstones its row
  (`deleted_at`): no read returns it, and a later `PUT` for the same id
  revives it with no keys and named in no statement.
- **Hilt UCAN RPC API** (`pkg/rpc`, ucantone server mounted at `POST /`) — the
  `/s3/*` commands Ingot (the S3 gateway) invokes: `/s3/request/authorize`,
  `/s3/bucket/{create,delete,info,list,policy}`; and the self-issued admin
  commands. `/s3/bucket/policy` carries the S3 GetBucketPolicy,
  PutBucketPolicy and DeleteBucketPolicy operations (the request's method
  selects), reached with a service key holding the matching permission; a
  PUT's body must hash to the signed payload hash. Policy writes are
  unconditional, as on AWS: If-Match and If-None-Match are ignored.
  The admin commands are
  `/admin/provider/{add,list}` and `/admin/provider/nodes/set` (`hilt client admin`).
- **Sprue** (the Forge upload service) — Hilt calls it to provision/inspect a
  bucket's storage space and to manage routing policies (`pkg/client`): each
  provider owns a policy whose candidates are its storage nodes, and every
  bucket's space is pointed at its provider's policy on creation.
- **Swarf** (the revocation service) — Hilt calls its `/ucan/revoke` to
  revoke delegations, every revocation of one write in a single request
  (`PublishBatch`): a deleted key's grants, a deleted bucket's, and the grants
  a policy change or a principal removal takes off a principal-bound key
  (`pkg/grant`). Each write publishes inside its transaction before it writes
  anything, so a failed publish leaves everything in place. No revocation carries a nonce, so a retry is a duplicate
  Swarf records once.
- **PLC** (the did:plc directory) — Hilt creates a tenant's did:plc there on
  provisioning and deactivates it on deletion (`pkg/fx/plc.go`).

Module: `github.com/fil-forge/hilt` (Go 1.27). Sibling repos it builds on:
`ucantone` (UCAN primitives: `did`, `multikey`, `ucan/delegation`, `binding`,
`server`, `execution`), `libforge` (bound `commands/*`, `identity`, ucan helpers),
and `sprue` (the upload service; mirror its patterns where relevant).

## Commands

- Build / vet / test: `go build ./... && go vet ./... && go test ./...`. Run all
  three after changes — this is the standard loop.
- Run locally: `go run ./cmd serve --upload-service-id=<did>
  --upload-service-url=<url> --upload-product-id=<did>
  --revocation-service-id=<did> --revocation-service-url=<url>` (all required,
  no default; add `--storage=memory --vault=memory` to avoid external deps; see
  `cmd/main.go` / `pkg/config`).
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
  how the IAM scenarios run against ingot changes that the `:main` image does
  not carry yet. Until the published `:main` ingot image carries the IAM
  changes, the IAM scenarios skip unless `HILT_ITEST_INGOT_BINARY` is set (or
  `HILT_ITEST_IAM=1`); drop that guard once it does. CI runs the suite after
  the unit job, on pull requests, on pushes to `main`, and on manual dispatch
  (`.github/workflows/go-test.yml`). It sets neither override, so the IAM
  scenarios stay skipped there until the published image carries the change.
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
- `pkg/bucketpolicy` — bucket policy evaluation over libforge's
  `s3bkt.BucketPolicy` (`Decode`, `Validate`, `Canonical`, `Effective`,
  `Changed`); pure, no store or transport dependencies. The document type,
  its JSON parsing and structural checks, and the policy
  action allowlist live in libforge `commands/s3/bucket`. The package doc has
  the document shape.
- `pkg/grant` — an access key's stored delegations: `Issue` builds the
  tenant→key set both key kinds hold, `Rotator` rewrites a principal-bound
  key's set as its policies change. See the package doc.
- `pkg/store/{tenant,accesskey,bucket,delegation,provider,principal,bucketpolicy}` —
  each an interface with `memory` and `postgres` backends.
- `pkg/store/pglock` — the Postgres transaction helpers the stores share: the
  transaction a write's callback joins, and the single-row read mapping.
- `pkg/vault` (`memory`, `openbao`) — private-key storage; `paths.go` has the
  key path helpers (`TenantKeyPath`, `AccessKeyPath`).
- `pkg/client` — clients for external services: the Sprue `UploadClient`, and
  `pkg/client/management`, the partner-key REST client for the tenant API.
- `pkg/tracing` — OpenTelemetry: `Setup` installs the OTLP exporter for
  `serve`; the Echo server-span middleware; `SpanNamer`, which names a UCAN
  request's span for its commands; `Handler`, which gives each invocation its
  own span (applied in `NewUCANServer`, outside the authorization middleware);
  and the instrumented HTTP transport. A new outbound HTTP client should use
  `tracing.NewHTTPClient()`, or wrap its own transport with `tracing.Transport`.
- `pkg/migrations` — goose SQL migrations run on startup (unless skipped).
- `internal/testutil` — test-only helpers (random DIDs/issuers, testcontainers).

## Conventions

- **New packages go under `pkg/`**, not `internal/` (only test helpers live in
  `internal/`).
- **Stores**: an interface in `pkg/store/<entity>` with `memory` + `postgres`
  implementations kept in lockstep and exercised by one backend-parametrized test
  suite (`<entity>_test.go`). Add a method to all three (interface + both backends)
  and cover it in that suite.
- **Callbacks, no locks**: a write that another service must learn about runs
  in one transaction: read the row, run the caller-supplied callback (`fn`,
  which runs inside the write before it takes effect), commit. The callback's ctx carries
  the transaction (`pglock.WithTx`), and a store that opens its own through
  `pglock.Begin` joins it, so what the callback writes commits with the
  caller's write or not at all. A write that revokes delegations reads them,
  publishes their revocations (`grant.PublishRevocations`, which
  `Rotator.Rotate`, `Rotator.Revoke` and `Rotator.Publish` call), and only then
  writes rows. Keep the publish before the transaction's first row write:
  Postgres holds a written row until commit, so a write before the publish
  would make every other write to that row wait on the revocation service. A
  failed publish rolls the write back and leaves everything as it was; a
  publish that succeeded followed by a commit that failed leaves revoked
  grants still stored, the one window the gateway's revoked set covers
  (`pkg/api/service/bucketpolicy` and `grant.Rotator` document the sequence).
  No store takes an explicit row or advisory lock; a write waits only on the
  rows another uncommitted write has already changed, as Postgres makes it,
  and the pool bounds that wait (`lock_timeout`) and an idle transaction
  (`idle_in_transaction_session_timeout`). Every Postgres store statement
  outside `pglock.Begin` runs on `pglock.ResolveDBTX(ctx, s.pool)`, so a
  read inside a write's callback uses that write's connection: taking a second
  one from the pool deadlocks once concurrent writes hold them all. Reads that
  must agree with each other run in one `bucketpolicy.Store.Snapshot`, a
  read-only `REPEATABLE READ` transaction on Postgres (`/s3/bucket/info` reads
  a key's effective actions and its grants that way). Of two concurrent policy writes to
  one bucket, the one that commits last is stored, and the keys may hold both
  writes' delegations over the bucket. A rotation replaces only a key's
  delegations over the bucket it rotates (`ReplaceBySubject`), so rotations
  over different buckets never undo each other.
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
- **Invocation authorization** (ucantone's `server/middleware`, applied in
  `pkg/fx/rpc.go`): routes in the `ucanRoutes` group are served behind
  `NotSelfSigned` + `OnlySubject(serviceDID)`, so a caller must present
  authority the service delegated; the admin commands, which Hilt invokes on
  itself, join `ucanAdminRoutes` (`asAdminUCANRoute`) and are served behind
  `OnlyIssuer(serviceDID)` + `OnlySubject(serviceDID)`, the shape they are
  invoked with. A self-signed invocation (issuer == subject) needs no proofs and
  carries unattenuated authority under the UCAN rules, which is why nothing but
  the service's own key may issue one. Those checks are silent, so
  `middleware.LogRejections` (`pkg/rpc/middleware`, Hilt's own) goes outermost
  and logs what they turn away. Register a new handler with `asUCANRoute` unless
  the service invokes it on itself, and put the check in middleware rather than
  in the handler.
- **Authorization**: signature-bearing S3 commands authenticate via the
  `auth.Authorizer` service (SigV4/SigV4a verify + time bounds + issuer == tenant's
  provider + region served by that provider), which also classifies the operation
  and resolves every bucket it addresses within the tenant and the key's scope.
  Classification mirrors the gateway's router (`pkg/rpc/service/auth/operation.go`):
  `subresources` is S3's subresource vocabulary, each marked supported or
  not, and `bucketRoutes` / `objectRoutes` give the operation a supported
  one selects per method. A request naming two subresources, an unsupported
  one, or a route Hilt does not authorize is refused; other query parameters
  are ignored, as S3 ignores them. When a versitygw bump serves a new
  subresource, mark it supported and give it a route (and an operation) or
  it stays refused. A
  copy (`x-amz-copy-source` on a PUT) is two decisions: the write on the
  destination and `s3:GetObject` on the source (`s3:GetObjectVersion` when the
  source names a versionId). An operation S3 gives a second permission on its
  own bucket (`companionPermission`: GetObjectAttributes needs `s3:GetObject`
  too) is checked for both, and so is a header that adds one
  (`classification.readHeaders`: lock and tagging headers on a write,
  `x-amz-bypass-governance-retention` on a delete or retention write,
  `x-amz-bucket-object-lock-enabled` on CreateBucket). Every header a
  decision is taken from must be a signed header, which `RequirementsFor`
  refuses too for the gateway's local check. A body is read only for the
  operations `Operation.ReadsBody` names (DeleteObjects: an entry naming a
  version adds `s3:DeleteObjectVersion`); the gateway attaches the body for
  those alone, and it must be bound to the signature (the payload hash, or a
  signed checksum header under an unsigned payload) before it is read;
  `MaxBodySize` matches the codec's limit on the field. Never
  widen that set to a write that streams its body; the policy PUT carries
  its document on its own command. Command-specific S3-permission checks
  stay in each handler. Both key kinds re-delegate from the key to the gateway on `/s3/request/authorize`,
  each per-request delegation keyed to itself. `/s3/bucket/info` carries no
  signed request, so it authorizes on the invocation issuer instead: the issuer
  must be the provider of the bucket's tenant, and the access key in the
  arguments must belong to that same tenant. It answers the proof chains from
  the bucket root through the key's stored grants over the bucket, and a
  principal-bound key's effective actions as its permissions.
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

## Observability

When a change adds or alters behavior someone depends on, decide how on-call
would see it working and see it fail, and add what's useful in the same PR:
logs, complete trace spans, and an alert or dashboard panel in
fil-forge/infra-central. Skip it for changes nothing operational depends on.
When a feature's health is best read as a number, say so in the PR
description, naming the metric and [FIL-1143](https://linear.app/filecoin-foundation/issue/FIL-1143).
`docs/observability.md` says how to do each.

## Security

Key material is sensitive. **Never log or echo private keys, secrets, or seed
material — log DIDs only.** The vault stores raw key bytes; only DIDs and CIDs
should appear in logs, errors, or test output. Secret-bearing CLI flags (vault
token, AppRole secret, partner key, etc.) warn to prefer `HILT_*` env vars or the
config file over process args; keep that guidance. Use placeholders (never real
values) for keys/tokens in examples and generated config.
