# Runtime architecture

This document describes the current `main` branch as implemented, including the boundary between hardware-proven paths and experimental SMP shard execution.

## 1. Boot stages

The machine boots through two binary images.

### Stage 1

`src/stage1/loader.asm` is the PXE network bootstrap program.

Its responsibilities include:

- finding the PXENV+ interface
- reading cached DHCP information while PXE firmware is still healthy
- publishing stable network handoff data for the runtime
- downloading `runtime.bin` through PXE TFTP
- protecting the firmware's low-memory stack from the growing runtime image
- closing TFTP before restoring the protected runtime region
- transferring execution to the runtime

The runtime image begins at physical `0x20000`.

A hardware-specific problem discovered during bring-up was that the PXE firmware stack occupied memory later covered by the runtime image. The loader now temporarily stashes the overlapping runtime bytes in low memory until TFTP is closed.

## 2. Runtime transition

The runtime begins in 16-bit mode, collects machine information, builds page tables, and enters x86-64 long mode.

The 16-bit bootstrap stack is intentionally placed below the runtime image. An earlier stack placement inside the runtime silently corrupted code and eventually produced invalid-opcode faults.

Once in long mode the runtime initializes:

- CPU protections and exception handling
- timing
- heap
- PCI discovery
- SMP/AP startup
- crypto
- network runtime
- filesystem/config
- shell
- bare-metal HTTP panel

## 3. SMP

The SMP subsystem discovers processors from ACPI/MADT and starts APs through the runtime trampoline.

On the currently tested hardware:

```text
threads/core      2
cores/package     2
logical/package   4
online CPUs       4
```

The AP worker dispatcher is hardware-proven.

### Stable mode

The production-like test path still runs shard networking and protocol state machines on the BSP. This is the current default because it has successfully brought the full 128-shard local pool to READY.

### Experimental parallel mode

An AP shard worker exists and partitions shard contexts by worker ID. Lifecycle and TCP work can therefore run across separate CPUs.

The primary obstacle is not shard-context ownership; it is old crypto code that was originally written for a single execution thread.

Several crypto implementations use global scratch workspaces, including:

- SHA-256
- HMAC/TLS PRF
- X25519
- AES-GCM
- RSA
- X.509/DER parsing

The experimental SMP path therefore uses a global crypto critical section around non-reentrant work. It is deliberately disabled by default pending hardware validation.

## 4. Network stack

The runtime does not use a host operating-system network stack.

The path is approximately:

```text
Realtek NIC
  -> Ethernet
  -> ARP
  -> IPv4
  -> UDP / DNS
  -> TCP
  -> TLS 1.2
  -> WebSocket
  -> Discord Gateway
```

### DHCP handoff

Stage 1 extracts and publishes:

- client IPv4 address
- server IPv4 address
- gateway
- subnet mask
- router
- DNS server

This avoids calling back into PXE firmware after the runtime has replaced the firmware's original stack memory.

### Native NIC

The legacy runtime prefers the native Realtek polling backend once long mode is active.

The native TX implementation uses a single hardware descriptor, so higher-level code must treat TX availability as a shared resource.

## 5. TLS and X.509

The runtime implements the TLS path used by Discord Gateway itself.

The hardware-proven singleton path includes:

- TLS ClientHello
- TLS 1.2 cipher selection
- server certificate parsing
- local issuer-chain verification
- RSA signature verification
- X25519 key exchange
- client key flight and Finished
- authenticated application records

The sharded TLS implementation gives each shard its own high-level TLS workspace, transcript storage, keys, and record state.

Some low-level crypto primitives still use shared globals, which is why the experimental SMP scheduler must serialize crypto operations.

The client does not use a pre-generated TLS certificate/private key. Each connection generates its ClientRandom and ephemeral X25519 private key on the target using CPU RDRAND, then derives the TLS master secret and AES-GCM traffic keys from the X25519 shared secret. Public CA trust anchors are built into the runtime; Discord's live leaf certificate and signed ephemeral key arrive during the handshake.

For the complete key-generation path and marker-by-marker failure diagnostics, see [TLS.md](TLS.md).

## 6. Shard context ownership

The local pool supports up to 128 contexts.

Each context tracks or references private state for:

- global shard ID
- local slot
- lifecycle state
- Identify bucket
- TCP connection
- TLS session
- WebSocket session
- Discord Gateway state
- sequence number
- heartbeat timing and ACK state
- reconnect/backoff
- session ID / resume information
- last error

The stable BSP scheduler iterates these contexts serially.

## 7. Connection admission

Connection admission is intentionally tied to Discord Identify scheduling.

A new connection is allowed only after DNS is ready. This prevents a backlog of `CONNECT_ALLOWED` shards from accumulating while the shared resolver cannot yet produce a Gateway address.

The current local shell plan forces Identify concurrency to 1. New connections are therefore brought up in controlled waves rather than opening 128 Gateway sockets simultaneously.

## 8. Singleton takeover

The machine initially proves the original singleton Discord path.

When `shardstart` is invoked:

1. DNS must already be READY.
2. shard resources are prepared.
3. the singleton Gateway transport is stopped.
4. the shard scheduler takes ownership of Discord transport.

The DNS readiness gate exists so a failed or unresolved DNS path cannot take a healthy singleton bot offline merely because the user typed `shardstart`.

## 9. Gateway lifecycle

A normal shard path is:

```text
assigned
  -> admitted
  -> TCP
  -> TLS
  -> WebSocket HTTP 101
  -> Gateway Hello
  -> Identify
  -> READY
  -> heartbeat / ACK
```

Transient failures enter backoff and rebuild their connection state.

The runtime already demonstrates successful recovery from transient TCP/TLS failures during a 128-shard bring-up.

## 10. Controller

`controller/` contains the experimental multi-node planning service.

The intended model is:

- a global shard count
- multiple PXE nodes
- per-node local capacity
- contiguous leased shard ranges
- lease expiry to prevent duplicate owners

The runtime-side controller client and authenticated `/gateway/bot` discovery remain future integration work.

## 11. Important ownership rules

The following boundaries should be preserved when extending the project:

- PXE firmware is used only while its execution environment is safe.
- RX demultiplexing remains centrally coordinated.
- one shard context should have one writer during a scheduler dispatch.
- shared NIC TX must be serialized.
- non-reentrant crypto must be serialized or converted to per-CPU/per-context storage.
- Identify scheduling must respect Discord-provided session-start limits.
- shard ownership must eventually be lease-based across multiple machines.

These rules come from hardware failures already encountered during development, not from theoretical cleanup work.
