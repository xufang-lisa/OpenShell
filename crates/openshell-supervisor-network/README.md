# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## HTTP HITL limited MVP (default off)

This opt-in implementation resumes one immutable, frozen bodyless HTTP/1.1 REST
request using the captured trusted connection executable/ancestor identity.
Full post-wait current-executor lifecycle proof is explicitly deferred as an
authorized limited-MVP security optimization. Captured identity is not proof
against exec, inherited/transferred FDs, multiple holders or sample-to-write
drift. This exception does not qualify the full security contract or production.

The opt-in HTTP wait path can supply a `HeldProposalInput` to a supervisor-owned
`HeldProposalService`. Extraction cross-checks the frozen header, method, normalized
path and query projection, and uses the generation-pinned L4 owner with trusted
executable/ancestor paths and workspace. Query values, headers, body, command line
and raw request bytes never enter this proposal seam. The captured request remains
local; FORWARD preserves its original query when projecting the frozen request.

Automatic proposals accept only unambiguous literal destination/binary scopes and
canonical ASCII paths without glob syntax. They retain native case-insensitive
methods, GET-to-HEAD and executable-or-ancestor matching; absent query matchers do
not constrain queries. They do not introduce an exact matching mode.

Submission runs inside the existing bounded prewrite waiter. Locking, RPC and
retry cannot extend the original deadline or outlive client cancellation. Waiters
may share a durable chunk, but retain independent IDs, cancellation and quota.
Transport ownership ends before its quota charge is returned. Accepted proposal
IDs and terminal events are locally correlated.

After acceptance, the same owner consumes read-only ledger observations from a
supervisor-wide coalesced batch reader. Rejected proposals terminate associated
waiters without inferring an actor from free-form rejection text. Approved
proposals still require native L4/L7 coverage of the frozen method/path/query and
captured executable/ancestor scope by the locally installed engine. Installation
wakes this check; unrelated reloads do not imply coverage. A weak engine reference
avoids a runtime ownership cycle. The actual narrowed destination port, not the
source endpoint's legacy first port, is used.

`ReviewProgress::CoveredNoAuthority { generation }` records an observation, never
a permit. Pending, unknown and approved-but-uncovered requests continue waiting
under the original lifetime and quota. Production uses
`HttpSession::wait_for_approval()` and `WaitReservation::readmission_guard()` to
hand the same Q to fresh admission in the observed installed generation. Stale
or lost policy observation terminates it; coverage alone never authorizes I/O.

[The production owner](src/proxy/held.rs) reauthorizes captured trusted scope,
pins same-generation native L4/L7 policy and route, rejects TLS skip/uninspected
routes, and repeats destination planning, controlled DNS/IP/SSRF/allowed-IP and
applicable upstream TLS validation. It discards the old upstream. Only after
admission does [the one-shot relay](src/l7/relay/held.rs) run current request and
response middleware, live credential preparation and native guarded forwarding.
It must obtain a fresh credential snapshot after admission through live provider/
resolver handles, not freeze credential generation or values at request capture.
This is the intended design; revision/installation guards recheck pending writes
and flushes, including re-polls.
Middleware cannot change the frozen method/path/query/request line or add a body.
FORWARD derives a native origin-form outgoing copy without losing the query;
the frozen original is never mutated.

`ApplicationFence` wraps the application stream **after** fresh upstream TLS.
Every `poll_write`, `poll_flush` and `poll_shutdown`, including Pending re-polls, checks policy,
workspace and the original runtime/epoch lifetime. The capture deadline (at most
300 seconds) remains active until the first positive HTTP application write;
TCP/TLS setup, Pending and zero-length writes do not retire it. Runtime and policy
cancellation continue through the response. `HeldUpstream` additionally checks
live credential revision/installation and policy on each write/flush. The owning
operation independently watches original-client EOF/errors or extra input, policy
staleness and runtime cancellation. Limits remain 16 per sandbox and conservatively
4 per destination across binaries; quota survives approval/first write until
transport drop.

At most one attempt sends Q and returns one response on the original client
TCP/TLS, then closes both sides; no keep-alive/pipeline migration, reconnect,
retry or replay, including after partial writes, flush or response failures.
TLS retirement may be drop/EOF rather than clean `close_notify`.

The OCSF `HTTP_HITL_EXCHANGE` terminal outcome is `not_sent` before a positive
HTTP application write, `response_observed` when a started relay returns a
response successfully, or `effect_unknown` when a started HTTP exchange fails.
`response_observed` does not imply business success. No outcome permits retry.
Session WAIT/PROPOSAL admission messages now describe awaiting review/fresh
admission; REVIEW says observation is not execution authority, not release disabled.

Historical no-release fixtures remain intentional:
`HttpSession::wait_no_release()` still uses `readmission_end()` and returns
`CurrentExecutorUnavailable` when its lifetime/generation checks pass. The
test-only `relay_http_stream()` adapter selects that path. These results and
historical release-disabled logs do not describe the current production resume
path. A terminal unsent-waiter “no release” log remains accurate.

Final full-lib, Clippy, production-ingress and direct `ApplicationFence` results
are centralized in the [final local evidence record](../../../HITL/http-hitl-readmission-boundary-implementation-zh-CN.md#final-local-evidence).
Ingress fixtures cover explicit/virtual CONNECT, FORWARD and independent client/
upstream TLS 1.2/1.3 combinations; [direct fence tests](src/proxy/held/tests.rs)
cover Pending/zero/first-positive writes, deadline, runtime, policy, workspace
and write/flush/shutdown. No live Gateway/Podman validation or production
qualification is claimed. CLI displayed-snapshot binding (step 5),
durable decision history/CAS and the full executor fence remain gaps. OCSF
correlation must not include request bytes, queries, review tokens or secrets.
