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

## HTTP HITL proposal boundary

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

Submission runs inside the existing bounded no-release waiter. Locking, RPC and
retry cannot extend the original deadline or outlive client cancellation. Waiters
may share a durable chunk, but retain independent IDs, cancellation and quota.
Transport ownership ends before its quota charge is returned. Accepted proposal
IDs and terminal events are locally correlated; no approval/coverage consumption,
fresh execution admission or HTTP release is implemented by this seam.
