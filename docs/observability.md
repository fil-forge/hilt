# Observability

How Hilt's logs, metrics and traces reach Grafana, and where its alerts and
dashboards go.

## Logs

Logs are what reaches Grafana today. This service runs in Forge Central, whose
CloudWatch logs and AWS metrics (load balancer, ECS, RDS) ship to Grafana; its
own metrics don't yet
([FIL-1143](https://linear.app/filecoin-foundation/issue/FIL-1143): Instrument
Hilt to provide useful telemetry). Log a failure an operator would act on at
error level, with the context needed to act on it (DIDs and CIDs, never key
material), in a stable message an alert can match.

Every HTTP request gets a `request_id` (the caller's `X-Request-Id` when it
sent one of at most 64 letters, digits, `.`, `_` or `-`, otherwise a
generated one, returned in the response's `X-Request-Id`), and its request line
(`request completed`, `client error` or `server error`) carries it. UCAN
invocations all arrive as `POST /`, so each invocation that reaches a handler
also gets an `invocation handled` line with its `command`, `issuer`, `subject`,
`invocation` CID, the same `request_id`, `ok`, the `failure` name and `error`
when it failed, and `took`. An invocation the server refuses before that, such
as one whose signature or proofs do not validate, gets no such line. One
request can carry several invocations of a command, which are handled as one
batch, so `took` is the batch's duration.
Work a handler logs for an invocation carries its `request_id` and
`invocation` too: add `reqlog.Fields(ctx)` (`pkg/reqlog`) to the line.

To find what a bucket policy write did, follow its ids:

- `wrote bucket policy over S3` and `deleted bucket policy over S3` name the
  `tenant` DID, `external_id`, `bucket` name and `bucket_id` DID, with
  `started` and `took` for the whole write.
- `prepared delegation rotation` (or `rotating delegations failed`) names the
  `tenant`, the `bucket` DID, the `principals` whose access changed, the
  `access_keys` it rewrote (each list in full up to ten entries, and always as
  a `_count`), and `started` and `took`. The write commits after this line, so
  its window ends at the policy line.
- An access key creation that a rotation reached first logs
  `access key was rotated while being created` with its `tenant`,
  `external_id`, `principal` and `access_key`, and its error names the same.
  The rotation line that lists that `access_key` is the policy write that
  raced it.

## Metrics

When a feature's health is best read as a number, such as a failure count, a
queue depth or the time of the last success, say so in the PR description,
naming the metric and
[FIL-1143](https://linear.app/filecoin-foundation/issue/FIL-1143), so it can be
carried to the issue and instrumented when the service exports metrics.

## Traces

Traces don't reach Grafana from Central yet either, but keep the spans complete
for when they do: new work runs inside the request's span, and a new outbound
HTTP client uses `tracing.NewHTTPClient()` (`pkg/tracing`).

## Alerts and dashboards

Alerts and dashboard panels live in fil-forge/infra-central, under
`terraform/envs/grafana/`; its `docs/observability.md` ("Adding an alert or
panel") says how to add them. Open a companion PR there, or say in this PR that
one is needed.
