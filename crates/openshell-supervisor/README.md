# OpenShell supervisor

The supervisor loads and reconciles policy, maintains provider credentials, applies network and MCP inspection, and drives the admitted isolation backend through attachment, confirmation, and workload start.

## Backend startup

The public `run_sandbox` entry point selects the OpenShell Sandbox Protocol backend and collects its startup inputs into a public `SandboxRunConfig`. Shared startup receives that config and the trusted backend setup separately. The `backend_setup` module owns that backend's launch-data decoder, workload policy discovery, and client construction. Descriptor contents cannot select an implementation.

Shared startup checks the admitted backend name before passing the opaque payload to its decoder. It then compares the decoded sandbox, session, and runtime generation with the trusted launch inputs before installing credentials or discovering workload policy. A mismatch stops startup.

The built-in decoder also carries the VM driver's fixed workload identity into shared policy validation. Startup and later policy updates must reject selectors that conflict with that identity. Other launch descriptors do not enable this VM-specific check.

The supervisor admits policy and prepares credentials before constructing and attaching the selected client. It uses the concrete RPC client handles `BoundBoundary` and `ConfirmedBoundary` from `openshell-sandbox-backend`: confirm the attached boundary, prepare network mediation, then start the workload. Backends supply native enforcement evidence through the Sandbox Protocol; the client validates it before exposing the confirmed handle.

The client receives the supervisor's live provider state, bearer-token slot, and CA-path slot. Provider refresh, token rotation, and later CA publication must remain visible through those shared handles. Startup does not create independent copies of their current values.

`backend_setup`, `SandboxRunConfig`, and `run_sandbox_with_backend` are public so the supervisor binary can select a registered backend. External backends should implement the `IsolationBackend` and `SandboxProtocol` services rather than link this crate.

The startup result separates the backend transport payload from optional
authenticated CONNECT listener settings. Shared networking starts the listener
only after boundary attachment and confirmation; the supervisor owns policy
evaluation, live credentials, and listener lifetime. These settings do not add
a proxy hook to the isolation interface or the shared Sandbox Protocol descriptor.

## Console logging

Diagnostics and OCSF shorthand share a bounded, nonblocking stderr writer. With `ocsf_json_enabled=true`, the same writer also receives timestamped `OCSF-JSON` records. Each formatter submits a complete line in one write so concurrent producers cannot interleave records in the queue. The 1,024-line queue drops new lines when full rather than waiting for stderr.

Console JSON is installed independently of optional file appenders and uses an INFO filter independent of the diagnostic filter. Its runtime enabled flag and target schema version are shared with the existing JSONL file layer. The supervisor retains the writer guards until shutdown. The gateway log push layer continues to emit shorthand only.

## Safe runtime and parent liveness

The supervisor drives the safe isolation-backend contract and network/policy
orchestration. Its library and executable forbid unsafe code.

For a VM host supervisor, the VM driver passes its parent-liveness pipe as stdin
and sets the private `--parent-liveness-stdin` flag. A dedicated reader terminates
the supervisor when the driver closes its write endpoint or exits. The driver
protects both original pipe endpoints with close-on-exec and lets `Stdio` transfer
the read endpoint to the child's stdin. The supervisor uses the standard stdin
reader and does not adopt a numeric raw descriptor. This mode reserves stdin for
liveness; sandbox workload input travels over the boundary protocol.

## Portable supervisor access

The supervisor consumes the shared isolation backend contract. Its gateway
session, canonical process attachment, and TCP readiness do not require SSH or
a Unix host.

TCP readiness opens only after the gateway accepts the authenticated session.
Session loss closes readiness; accepted reconnection restores it. Dropping the
readiness guard closes the listener. A requested Unix readiness endpoint fails
explicitly on unsupported hosts, even before session acceptance.

The optional Unix SSH adapter remains separate from boundary-based process I/O.
The process-access multiplexer consumes boundary-provided streams and delegates
terminal resizing and signals through the existing isolation contract. It does
not own local PIDs, PTYs, or process-group signaling; native process operations
belong to the sandbox or isolation backend. Signals use `BoundarySignal`.

These portable control-plane foundations do not qualify a platform isolation
backend or enable a Windows workload runtime.

## Held HTTP proposals and limited-MVP execution (default off)

When gateway/sandbox inputs are available, startup installs the internal HTTP HITL
proposal service before networking. This does not enable the default-off wait
setting. Admitted requests use a non-generalizing mode of the existing mechanistic
mapper and the existing authenticated `SubmitPolicyAnalysis` RPC, independently
of the background agent-proposals aggregator.

One launch UUID plus a content fingerprint supplies stable retry IDs. Submission
is serialized with one-second attempt spacing, a ten-second connect/RPC timeout,
and a sixteen-entry accepted-ID cache. Current workspace is checked across awaits.
No detached per-request submission task is created. The gateway persists a
namespaced deduplication key, preserves edited/terminal chunks on retry, isolates
these proposals from endpoint-folding/supersession, and excludes them from
auto-approval. These labels do not authenticate supervisor provenance.

Native GET/HEAD, method folding, query and executable-or-ancestor effects are
explicit in the review rationale. This increment neither changes policy matching
nor turns proposal acceptance into execution authority. The current network
owner can separately resume an approved, installed-and-covered frozen request.

The service also reuses authenticated `GetDraftPolicy` for read-only decision
observation. Active waiter futures cooperatively share one sandbox-wide batch,
at most one fetch per second (also spaced after slow completions), with a
ten-second connect/RPC bound, a 256 KiB response bound and a 1024-chunk limit.
Only IDs and typed ledger statuses are cached; tokens, reasons and candidate
contents are discarded. Unknown/missing statuses and transient read failures
cannot grant coverage; permanent failures terminate safely. Cancellation drops
the owning operation and releases its lock, without detached polling tasks.

Approved is separate from locally installed coverage. Startup attaches a weak
reference to the live policy engine for coverage-only observations. Held drafts
are excluded from automatic covered-policy queue rejection, while ordinary
draft behavior is unchanged. Ledger rejection is deliberately not labelled as
human attribution, since the current API does not expose a decision actor.
After approval and coverage, the network owner now attempts a fail-closed
readmission boundary using the captured trusted connection executable/ancestor
identity for the immutable original request. Full current-executor continuity
through exec, inherited/transferred FDs, multiple holders and first write is
explicitly deferred by the authorized limited-MVP scope, not proved by coverage
or by the captured identity. The full target contract remains unmet.

The [network owner](../openshell-supervisor-network/src/proxy/held.rs) uses
`wait_for_approval()` and `readmission_guard()` to pin the observed installed
generation, then repeats native L4/L7 authorization, route and destination
DNS/IP/SSRF/allowed-IP checks and applicable fresh upstream TLS. The
[one-shot relay](../openshell-supervisor-network/src/l7/relay/held.rs) applies
current middleware and live credential preparation with native policy and
credential revision/installation guards. No old upstream authority is reused.
Fresh credential snapshots must be obtained after admission through live provider/
resolver handles; freezing credential generation or values at capture is not the
design. Guards continue to protect pending writes and flushes on every re-poll.
Coverage itself is still not an execution permit.

After TLS, `ApplicationFence` checks every application write/flush/shutdown poll,
including Pending re-polls. The original capture deadline lasts until the first
positive HTTP application write, not until TCP connect or TLS handshake.
Workspace, runtime/epoch, policy and original-client cancellation remain active
through the exchange. Pending/uncovered requests retain their original wait
lifetime; quota is returned only after transport drop, never at approval or
first write. One frozen request returns one response over the original client
TCP/TLS, then both sides close; errors never cause reconnect/retry/replay.

OCSF terminal exchange outcomes distinguish `not_sent`, `response_observed` and
`effect_unknown` (HTTP started, then the exchange failed). A response observation
does not imply business success, and no outcome permits retry. Session WAIT and
PROPOSAL admission logs now describe awaiting review/fresh admission; REVIEW
explicitly says observation is not execution authority, not release disabled.

`wait_no_release()` / `readmission_end()` and legacy test adapters retain the
historical `CurrentExecutorUnavailable` behavior. They are not the current
production path; older no-release results must not be used to describe it.
The [final local evidence record](../../../HITL/http-hitl-readmission-boundary-implementation-zh-CN.md#final-local-evidence)
centralizes completed full-lib and Clippy results, production-ingress coverage
including original-client TLS 1.2/1.3 combinations, and direct application-fence
write/flush/shutdown tests. These are not live Gateway/Podman validation. Full executor
proof, CLI snapshot binding (T5), durable decision history/CAS (full T6), and
production qualification remain outstanding. Snapshot polling can miss an
intermediate rejection/reapproval; no durable decision-revocation fence is claimed.
