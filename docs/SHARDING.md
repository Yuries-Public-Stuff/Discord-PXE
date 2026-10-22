# Sharding design

This repository is the multi-shard evolution of the original bare-metal `discord-pxe` runtime.

The early refactor milestones are complete enough that the local runtime can now bring a full **128-shard pool** online on real hardware in stable BSP scheduler mode.

This file describes the current design and the remaining work.

## Local capacity model

A physical PXE node can own up to 128 local shard contexts.

Two numbers must remain separate:

- **global shard count** — the Discord bot's total shard count
- **local shard count** — the number of shard contexts assigned to this physical node

A node may therefore own a contiguous subset of a larger global shard plan.

## Per-shard state

Each local shard context owns or references independent state for:

- shard ID
- total global shard count
- local slot
- lifecycle state
- Identify bucket
- TCP context
- TLS context
- WebSocket context
- Discord Gateway context
- Gateway sequence
- heartbeat deadline and ACK tracking
- session ID / resume URL
- reconnect/backoff state
- last error

This separation is what allows 128 distinct Gateway connections to coexist in one runtime.

## Scheduler

### Stable BSP scheduler

The default scheduler currently walks all active contexts on the bootstrap processor.

For each shard it advances:

```text
lifecycle
TCP
reliable TCP
TLS
Discord Gateway
```

Global connection admission and Identify arbitration are also performed centrally.

This path is hardware-proven through a complete 128-shard READY run.

### Experimental SMP scheduler

The source also contains an AP worker that processes disjoint strided subsets of the shard pool.

The intended ownership rule is:

```text
worker 1 -> one subset of shard contexts
worker 2 -> another subset
worker 3 -> another subset
BSP      -> global admission / arbitration / RX coordination
```

The first SMP hardware test exposed global scratch memory inside crypto primitives. Each shard still owns separate TLS keys and session state; the race was in temporary implementation workspace, not intentional key sharing.

The current experimental implementation therefore keeps shard lifecycle/TCP work parallel but places non-reentrant crypto operations behind a shared critical section.

Parallel shard execution remains disabled by default until this corrected model passes hardware validation.

## Identify scheduling

Discord's Identify `max_concurrency` is a server-provided session-start property.

It must not be guessed from:

- CPU count
- number of local shard workers
- local shard count
- a user-supplied test value

The runtime's local shell plan therefore forces:

```text
max_concurrency = 1
```

until the authenticated `/gateway/bot` REST path is implemented.

Connection admission is coupled to the Identify schedule so the machine does not open a large set of Gateway sockets that sit waiting for minutes before they may Identify.

## Connection admission

A shard may receive `SHARD_FLAG_CONNECT_ALLOWED` only when:

- shard networking is enabled
- DNS is READY
- the current connection wave permits its Identify bucket
- its TCP context is idle
- it is not in a fatal state

This prevents a previously observed failure mode where connection permissions accumulated while DNS was unresolved and were all released later as a backlog.

## Singleton takeover

Boot initially uses the singleton transport as a control path.

The singleton proves:

- DNS
- TCP
- TLS/X.509
- WebSocket
- Discord authentication

Only after that path is healthy should local sharding take over.

`shardstart` now requires DNS READY before shutting down the singleton Gateway connection.

## Reconnect behavior

A shard connection can enter backoff after a transient TCP/TLS failure.

The runtime rebuilds connection state and retries after the backoff interval.

Hardware testing has demonstrated shards recovering from transient failures and reaching READY again.

Long-term lifecycle work still includes stronger Discord Resume behavior rather than treating every recoverable disconnect as a fresh Identify opportunity.

## Controller model

The experimental controller in `controller/` plans shard ownership across machines.

The design is lease-based:

```text
controller
  -> global shard plan
  -> node capacity
  -> contiguous local assignment
  -> lease generation + expiry
```

A node must stop shard-owned traffic when its lease expires so another machine can safely receive that ownership.

The runtime already contains local lease expiry behavior. Full controller-to-runtime integration remains future work.

## Required `/gateway/bot` integration

Before local plans can safely use concurrency greater than 1, the runtime needs an authenticated REST client for:

```text
GET /api/v10/gateway/bot
```

The relevant response fields include:

```text
url
shards
session_start_limit.total
session_start_limit.remaining
session_start_limit.reset_after
session_start_limit.max_concurrency
```

That data should drive:

- recommended global shard count
- verified Identify bucket count
- whether a new Identify may be consumed at all
- how long the runtime must wait for session-start reset

## Remaining milestones

Recommended implementation order:

1. expose `shardsmp on|off|status`
2. validate SMP with 8 shards
3. scale SMP validation 8 -> 16 -> 32 -> 64 -> 128
4. keep stable BSP fallback until the full SMP run is clean
5. implement `/gateway/bot`
6. honor remaining/reset session-start limits
7. complete Resume semantics
8. wire live controller check-in/lease renewal into the runtime
9. add authenticated controller transport and durable device identity
10. consider per-CPU/per-context crypto scratch to reduce serialized crypto time

## Design constraints learned from hardware

Several constraints are now intentional because violating them caused real failures:

- do not call back into PXE firmware after overwriting its original stack environment
- keep runtime bootstrap stacks outside the runtime image
- do not guess Discord Identify concurrency
- do not take down the singleton before basic network readiness
- do not assume private shard TLS contexts imply re-entrant low-level crypto
- do not allow multiple CPUs to mutate one shard context simultaneously
- treat native NIC TX as shared hardware state
- retain a stable BSP path while SMP work is still experimental

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full runtime layering, [TLS.md](TLS.md) for TLS key generation and SMP crypto debugging, and [STATUS.md](STATUS.md) for what is hardware-proven.
