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
  PUT's body must hash to the signed payload hash, and If-Match /
  If-None-Match are optional signed headers (absent means unconditional).
  `/s3/usage/report` is the one command a provider invokes on its own
  authority: Ingot's own counts of the bytes it sent from each bucket in each
  hour, which the tenant and bucket metrics endpoints serve as their egress
  series, and of the objects each bucket has gained and lost over its life as
  of each hour, which they serve as the storage series' object count
  (`pkg/store/usage`). Every count is a total that only grows and Hilt keeps
  the largest reported, so a report is safe to repeat or to deliver late. A
  bucket holds the objects it has gained less those it has lost, read from
  the latest hour reported; the upload service's count of uploads is not
  read. Counts for a bucket
  Hilt never knew, or one another provider serves, are left out and come
  back as a named warning beside the result rather than failing the report; a deleted bucket's are kept,
  attributed through `bucket.Store.Owner`, which outlives the bucket.
  The admin commands are
  `/admin/provider/{add,list}` and `/admin/provider/nodes/set` (`hilt client admin`).
  The route takes no credential and an invocation's issuer is resolved before
  its signature is checked, so a `did:web` issuer is fetched only when it is
  Hilt's own DID (answered locally) or a registered provider's
  (`pkg/fx/provider_resolver.go`). Any other `did:web` is refused without a
  request; a provider registered while Hilt runs is recognized within ten
  seconds.
- **Sprue** (the Forge upload service) — Hilt calls it to provision/inspect a
  bucket's storage space and to manage routing policies (`pkg/client`): each
  provider owns a policy whose candidates are its storage nodes, and every
  bucket's space is pointed at its provider's policy on creation.
- **Swarf** (the revocation service) — Hilt calls its `/ucan/revoke` to
  revoke delegations, every revocation of one write in a single request
  (`PublishBatch`): a deleted bucket's grants, and the grants
  a principal removal takes off a principal-bound key
  (`pkg/grant`). No revocation carries a nonce, so a retry is a duplicate
  Swarf records once.
  Revocations recorded as owed (`pkg/store/revocation`) are published from
  the task queue instead, in batches, and retried until Swarf takes them
  (`pkg/tasks/revocationqueue`). A tenant status change into or out of
  `disabled` records them: disabling withdraws every grant the tenant's keys
  hold, and leaving `disabled` withdraws whatever they hold and issues each
  key fresh grants. An access key's deletion records the grants the key held,
  and a bucket policy's write or removal records the grants over the bucket
  it takes off the affected principals' keys
  (`pkg/tasks/tenantqueue`). Tenant deletion publishes what
  is still owed itself, before it deactivates the tenant's DID, which Swarf
  verifies the revocations against.
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
  no default; storage is always Postgres, `--postgres-dsn` names the database,
  and `--vault=memory` avoids running OpenBao; see `cmd/main.go` /
  `pkg/config`).
- Every test that touches a store runs on Postgres, and the OpenBao tests on
  OpenBao, both through testcontainers (`internal/testutil`). They **skip when
  Docker is unavailable** (and fail on a Linux CI runner), so `go test ./...`
  without Docker passes while covering little; run it with Docker. A test gets
  its database from `testutil.PostgresOrSkip(t)`: each test binary starts one
  Postgres container on first use and migrates a template database once, and
  every call returns a pool on a fresh database copied from that template and
  dropped when the test ends. Seed the rows the foreign keys reference
  (provider, tenant, principal, bucket) before the rows that point at them.
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
  how a scenario runs against peer changes that the `:main` image does not
  carry yet. CI runs the suite after the unit job, on pull requests, on pushes
  to `main`, and on manual dispatch (`.github/workflows/go-test.yml`), against
  the published images.
- Editor/LSP diagnostics can lag after cross-file or cross-package edits —
  `go build` / `go vet` are authoritative, prefer them over stale squiggles.

## Layout

- `cmd/main.go` — cobra entrypoint (`serve`).
- `pkg/fx` — uber-fx wiring. `AppModule` wires the Postgres stores and picks
  the vault (`memory`/`openbao`) backend from config; `ProvideConfigs` splits
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
  its JSON parsing and structural checks, ETag calculation, and the policy
  action allowlist live in libforge `commands/s3/bucket`. The package doc has
  the document shape.
- `pkg/grant` — an access key's stored delegations: `Issue` builds the
  tenant→key set both key kinds hold, `ForKey` the set of one key, and
  `Rotator` revokes what a removed principal's keys hold. See the package
  doc.
- `pkg/store/{tenant,accesskey,bucket,delegation,provider,principal,bucketpolicy,usage,revocation}` —
  each an interface with its `postgres` implementation.
- `pkg/store/pglock` — the Postgres locking helpers the stores share: bounded
  lock waits, advisory locks, and the mapping to `store.ErrLockTimeout`.
- `pkg/tasks` — the durable task queues, run on libforge's `taskrunner`
  (read its README before writing a handler). `tasks.go` names the queues, in
  order, and their actions: `queue-tenant` for changes to a tenant's
  authority and `queue-revocation` for publishing revocations, both on the
  subject of the tenant's DID string. Each queue's handlers live in a package
  under it (`tenantqueue`, `revocationqueue`). `queue-tenant.set-status` is
  the tenant status change, which `tenant.Service.SetStatus` submits and
  waits for. `queue-tenant.create-key` and `queue-tenant.delete-key` create
  and delete an access key, submitted and waited for by
  `accesskey.Service`, which keeps the key's secret to itself: it writes the
  secret to the vault before it submits the creation and removes it when
  the task fails. `queue-tenant.put-policy` and `queue-tenant.delete-policy`
  write and remove a bucket's policy, submitted and waited for by
  `bucketpolicy.Service` (`pkg/api/service/bucketpolicy`): one commit writes
  the document, withdraws the grants over the bucket of every key of each
  principal whose effective actions change, and stores the grants the new
  document gives them. A task's arguments that carry more than one value,
  and a result that does, are a
  cbor-gen model under the queue's `datamodel` package (`go generate` in its
  `gen` directory). The runner is built with the Postgres store
  module (`pkg/fx/store/postgres`), which creates its tables in the `public`
  schema after the goose migrations; `pkg/fx/tasks.go` registers the handlers
  and starts and stops it with the service.
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
- **Stores**: an interface in `pkg/store/<entity>` with one implementation,
  `postgres`, exercised by the suite in `<entity>_test.go`. Add a method to the
  interface and the implementation and cover it in that suite.
- **Locking and callbacks**: the writes that do not run as tasks yet
  (principal removal, bucket deletion, tenant deletion) and must tell another
  service run in one transaction: lock the row (`SELECT … FOR UPDATE`), run
  the caller-supplied callback (`fn`, which runs inside the write before it
  takes effect), commit. The callback's ctx carries
  the transaction (`pglock.WithTx`), and a store that opens its own through
  `pglock.Begin` joins it, so what the callback writes commits with the
  caller's write or not at all. A principal removal's callback publishes the
  revocations of its keys' grants before it deletes the keys, and a bucket
  deletion's those of the bucket's grants before it deletes the bucket, so a
  failed publish rolls the write back and leaves it retryable. A reader that
  must not be answered from a snapshot older than an in-flight write passes
  `store.WithShareLock()` (`SELECT … FOR SHARE`). Every lock wait is bounded by
  `store.LockTimeout` and a statement that gives up returns
  `store.ErrLockTimeout`, which the caller retries.
- **Tasks**: a handler reads through its stores and writes only through
  `ex.Write`, with a `store.Statement` the store builds, so the write commits
  with the task; it never reads a row its own task wrote. A task's arguments
  and result are stored in Postgres, so no secret goes into either. Write an
  action with its queue (`queue-revocation.publish`). The runner refuses a
  task that queues its own action, so a task does all of its work itself:
  the one publish task a change queues (`revocationqueue.PublishSpec`)
  publishes everything the tenant owes, reading each batch after the last
  row of the one before, because its own deletes are not visible until it
  commits. Principal removal and bucket and tenant deletion
  still write keys, grants and policies under locks, outside the queue. A
  task that withdraws grants therefore chooses the rows in the statements its
  commit runs (`delegation.Store.WithdrawKeyGrantsStatements`,
  `WithdrawGrantsOverStatements`, `WithdrawGrantsOfKeyStatement`), never from
  a list its handler read, takes the keys' delegation locks first when it
  goes on to store grants for them, stores grants only for keys that still
  exist (`PutForKeysStatement`), and
  makes the write of a value it read conditional (`ex.WriteConditional`). A
  task that issues grants or writes a policy from what it read opens its
  commit with the conditions that what it read still holds: a key creation
  share-locks its principal's row (`principal.Store.RequireLiveStatement`)
  and then checks the principal's policies are the ones it read
  (`bucketpolicy.Store.RequireUnchangedStatement`); a policy write takes
  the bucket's policy lock (`bucketpolicy.Store.LockStatement`), which a
  bucket deletion holds while it revokes, share-locks the rows of the
  principals its document names, and writes the document only over the
  policy it read (`bucketpolicy.Store.PutStatements`). Each of these
  safeguards names, in its doc comment, the writers it is there for, and
  goes when they move onto the queue. Tests build a runner on their test database with
  `testutil.StartTaskRunner`, or `testutil.StartServiceTasks` for one with
  the service's handlers registered.
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
  the service's own key may issue one. The one exception is the
  `ucanProviderRoutes` group (`asProviderUCANRoute`), served behind Hilt's own
  `OnlySelfSignedByProvider`: a registered provider invoking over itself, with
  Hilt as the audience. Its subject is the provider, so it claims none of
  Hilt's authority, and it belongs there only when all the command does is
  record what the provider says about itself. Those checks are silent, so
  `middleware.LogRejections` (`pkg/rpc/middleware`, Hilt's own) goes outermost
  and logs what they turn away. Register a new handler with `asUCANRoute` unless
  the service invokes it on itself or a provider invokes it over itself, and put
  the check in middleware rather than in the handler.
- **Authorization**: signature-bearing S3 commands authenticate via the
  `auth.Authorizer` service (SigV4/SigV4a verify + time bounds + issuer == the
  provider registered for the request's signing region), which also classifies
  the operation and resolves every bucket it addresses within the tenant, the
  key's scope, and that provider. Tenants are region-free; a bucket is bound to
  the provider (region) it was created through and only that provider may act on
  it (`BucketRegionMismatchError` otherwise).
  Once the request is authenticated and before the tenant's status is read,
  `Authorize` asks the task runner for the tenant's unfinished tasks on
  `queue-tenant` and waits for all of them, for up to `store.LockTimeout`,
  so no request is answered from a state a queued change is about to
  replace; a wait that runs out is `ErrTemporarilyUnavailable`. The access
  key is read before the wait, because it names the tenant, so a request
  that waited reads it again and is refused when the change it waited for
  deleted the key. Tenant status changes, access key creation and
  deletion and bucket policy writes and removals are queued there. The
  share-locked reads of the key, the principal and the policy stay for
  principal removal and bucket deletion, which hold those rows locked while
  they revoke, until they have moved onto the queue. The
  status is read before the policies and before the key's stored grants,
  and a status change commits its status and its grant changes together, so
  a change that lands between two of those reads leaves the answer no wider
  than the status read allows (the comment at the read in
  `pkg/rpc/service/auth/auth.go` has the cases).
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
  each per-request delegation keyed to itself. The cleanup commands among
  them (`/blob/remove`, `/blob/abort`) are also issued by
  the tenant for `CleanupLifetime` (8 days) past the next UTC midnight plus
  the clock skew, when the gateway stops reusing the response, keyed to the
  chain through the
  bucket's root, which rides back with them, so cleanup the gateway schedules
  outlives the key. The gateway must authorize requests locally only on
  chains the access key issued, or these would stand in for a request's
  authority once the key expires.
  `/s3/bucket/info` carries no
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
