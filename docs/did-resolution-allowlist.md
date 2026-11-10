# Inbound did:web resolution policy (FIL-1675)

Hilt's UCAN POST endpoint self-authenticates invocations. Validation needs an
issuer's key before it can verify that signature, so resolution is a pre-auth
boundary. Hilt now admits external did:web resolution only for exact identities
configured in `server.allowed_web_dids`. An empty configuration denies all
external web DIDs; it does not inherit ucantone's permissive empty-pattern
behavior. did:key works without HTTP and Hilt's own web DID resolves locally.

## Configuration and rollout

Use a YAML list or CSV `HILT_SERVER_ALLOWED_WEB_DIDS` / `--allowed-web-dids`.
An identity is a complete DID, for example `did:web:s3.region.stage.example.com`,
not a hostname pattern. Paths and encoded ports are part of that exact scope.
The authority must be a literal DNS hostname or IPv4 address; wildcard, userinfo,
IPv6/zone syntax and ambiguous/traversing or percent-encoded path settings are
rejected at startup. The method's `%3A`-encoded authority port remains supported.

The companion infra-central change derives the stage's exact incoming Ingot DID
inventory from active appliance regions and the configured Ingot hostname suffix.
It must be deployed with the binary. Outbound Sprue and Swarf clients are separate
from this inbound resolver and do not justify adding those identities to this
allowlist. Additional incoming proof issuers require source-backed inventory.

The policy rejects disallowed identities before DNS/HTTP and returns the same
policy error whether their target would be reachable, unreachable or return a
particular HTTP status. Every transport attempt, redirects included, is checked
against the exact configured DID-document URLs; an allowed source cannot redirect
to another host, port, path or query outside the set. Trusted allowlisted DNS is
still trusted: this is an application identity allowlist, not an IP-level egress
firewall or a general defense against compromise of an approved issuer.

Before enabling a new binary in a stage:

1. Confirm the generated allowlist contains the actual incoming Ingot identities
   for that stage and every intended did:web proof issuer; no blanket wildcard.
2. Roll the configuration and image together. Verify a legitimate Ingot command
   still reaches Hilt, and service-self and did:key commands still validate.
3. Against an authorized test listener, send an invalid-signature invocation
   naming a disallowed DID; assert no listener request and a policy-denial receipt.
   Repeat for a closed authorized endpoint; the failure reason remains policy.
4. Verify an allowed document redirects to an unauthorized local fixture only
   within a test environment and that fixture receives zero requests.

Do not roll back to an unrestricted resolver to recover missing caller inventory.
Correct the exact inventory, restart and repeat the legitimate call. No network
perimeter change or live deployment is part of this source fix.

## Observability

Startup logs `configured UCAN did:web resolution allowlist` with `identities`.
A policy denial logs `did:web resolution denied by allowlist` at debug level
with `did`; the caller receives `did:web resolution not permitted`. Logs contain
DIDs, not signing material. Debug avoids a warning/error per unauthenticated
probe. Existing invocation tracing retains validation failures. A sustained
failure for a known registered Ingot identity calls for comparing that exact DID
with the generated stage inventory, not broadening the policy.

For future metric export (FIL-1143), `hilt_did_resolution_denied_total` would be
a useful low-cardinality counter; do not label it with attacker-chosen full DIDs.
No new alert fires on every rejected arbitrary issuer. Companion infrastructure
observability guidance describes the existing CloudWatch/Grafana lookup.

## Validation scope

Tests use the actual unauthenticated Echo POST mount, UCAN container decoding,
DID resolver and signature validator. Local real HTTP listeners assert default
denial without requests, permitted resolution followed by InvalidSignature,
exact path/host matching and redirect escape denial. A TLS listener verifies the
HTTPS default with a fixture-only trusted certificate. Configuration tests cover
CSV environment parsing and the deny-all empty default. Tests do not call a live
Forge deployment or change its configuration.

Current source validation uses Go 1.27.0. `go build ./...` and `go vet ./...`
passed; the complete unit run recorded 1,259 passing test/subtest events, 28
skips and zero failures. Skips cover Docker-dependent Postgres/OpenBao cases;
these are not Docker integration acceptance. `go test -race ./pkg/fx ./pkg/config`
passed as well. Restoring the original unrestricted resolver as a temporary
negative control made the default-denial POST regression fail: its authorized
local canary was reached and the receipt carried HTTP 418 instead of policy
denial. The fixed resolver was restored before final checks.

This change bounds destinations; it does not add request rate limiting or claim
measured amplification behavior. Real stage activation and the controlled
listener acceptance after activation remain deployment work.

The pinned Smelt integration helper does not register a Hilt config-file mount or
forward arbitrary host variables. The Hilt test harness therefore uses the
existing image override to derive a tiny fixture-only image with the exact
`did:web:ingot` allowlist, then mounts the working binary as before. Its context
contains no repository files or credentials. A unique test-owned tag is removed
after the suite. Compilation/vet of this tagged harness is checked separately;
Docker execution remains unverified while its daemon is unavailable. A passing
ordinary unit suite never establishes this full-stack acceptance.

The integration harness compiled with
`go test -c -tags itest -o /private/tmp/fil-1675-hilt-itest.test ./itest` and
passed `go vet -tags itest ./itest`. These commands do not run `TestMain`, its
pre-test container sweep, image build or the stack. The Docker fixture runtime
still needs an authorized single-host integration run after the daemon starts.
