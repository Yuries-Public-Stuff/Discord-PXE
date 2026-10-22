# Hardware status

This file records what has actually been demonstrated on hardware versus what merely exists in source.

## Current tested machine

The current hardware logs show an Intel Haswell-class x86-64 system with:

- CPU signature `0x000306C3`
- 2 hardware threads per core
- 2 cores per package
- 4 logical processors
- 4/4 processors online
- native Realtek network backend

The project should not assume every machine has identical firmware memory layout or NIC behavior.

## Proven

### Boot and memory

- legacy BIOS PXE entry
- PXENV+ discovery
- DHCP handoff
- TFTP runtime download
- runtime image crossing the original PXE firmware-stack address range without corrupting active firmware
- long-mode transition
- E820-backed memory setup
- runtime bootstrap stack outside the runtime image

### SMP infrastructure

- MADT processor discovery
- 4 logical processors online
- AP startup
- AP worker dispatch
- parallel read-only shard-health work

### Network

- native Realtek backend
- IPv4 configuration from PXE/DHCP handoff
- router and DNS propagation
- ARP
- DNS resolution
- TCP to `gateway.discord.gg:443`

### Crypto/TLS

- RDRAND-backed RNG initialization
- SHA-256 / HMAC / PRF
- AES-GCM
- X25519
- RSA verification
- self-contained X.509 issuer trust store
- local certificate-chain verification
- authenticated TLS 1.2 session to Discord
- per-connection ClientRandom generation from CPU RDRAND
- per-connection ephemeral X25519 private/public key generation
- TLS master-secret and AES-GCM traffic-key derivation on target

### Discord singleton

- WebSocket HTTP 101
- Gateway Hello
- Identify
- READY
- bot online

### Sharding

- 128 local context slots
- isolated per-shard TCP/TLS/WebSocket/Gateway contexts
- local plan `128 0 128`
- conservative Identify concurrency of 1
- all shard IDs `0..127` reaching READY in one hardware run
- transient shard failure/backoff/reconnect returning to READY

## Stable default mode

The current default shard scheduler is **BSP mode**.

That means one CPU drives the active shard protocol state machines, even though all APs are online and available.

This mode is the current known-good 128-shard baseline.

## Implemented but not yet hardware-proven

### SMP shard state-machine execution

The source contains a scheduler that stripes shard contexts across AP workers.

The first hardware attempt exposed two classes of assumptions inherited from the single-threaded runtime:

1. shared packet/transmit state
2. non-reentrant crypto scratch buffers

The networking allocator and shared transmit path have been hardened, and the experimental AP worker path now serializes non-reentrant crypto sections.

That corrected design has not yet completed a clean hardware acceptance run, so parallel shard execution remains disabled by default.

## Known limitations

### No runtime `/gateway/bot` discovery

Local shell plans do not yet query Discord's REST API for:

- recommended shard count
- `session_start_limit.total`
- `session_start_limit.remaining`
- `session_start_limit.reset_after`
- `session_start_limit.max_concurrency`

Therefore local plans force Identify concurrency to 1.

### Session resume is incomplete as a production lifecycle

Shard state contains resume-related information, but reconnect behavior is not yet a complete production-quality Resume/Identify strategy for all close/error cases.

### TLS implementation and shared crypto

The runtime generates ephemeral TLS key material at runtime rather than shipping a client TLS private key. Public CA trust anchors are built in; live server certificates are received and verified during the handshake. See [TLS.md](TLS.md) for the exact key schedule and troubleshooting flow.

### Shared crypto implementation

Several primitives use global scratch memory and are not naturally re-entrant.

The long-term fix should be one of:

- per-CPU scratch storage
- per-shard crypto workspace
- explicit serialized crypto service

The current experimental SMP path uses serialization.

### Single native TX descriptor

The tested Realtek path uses one native TX descriptor. It is adequate for the stable scheduler and must be treated as a shared serialized hardware resource under SMP.

### Gateway intents

The current Identify payload uses `intents: 0`. Features that depend on privileged or nonzero Gateway intents require deliberate implementation and configuration.

### Embedded bot credential

The build can embed the bot token into generated runtime data. A built runtime containing a real token must be treated as secret material.

## Next engineering milestones

Recommended order:

1. add a runtime `shardsmp on|off|status` switch
2. validate AP shard execution with 8 shards
3. scale SMP validation through 16, 32, 64, and 128
4. keep BSP mode as an immediate fallback until the 128-shard SMP soak is clean
5. implement authenticated `/gateway/bot` discovery
6. respect session-start remaining/reset limits
7. complete Resume handling
8. integrate controller leases with the live runtime
9. consider replacing global crypto scratch with per-CPU or per-context storage

## What not to regress

When changing low-level code, always re-prove these milestones in order:

```text
PXE/TFTP
-> long mode
-> native NIC
-> DNS
-> singleton TCP
-> singleton TLS/X509
-> singleton WebSocket READY
-> small shard pool
-> 128-shard BSP baseline
-> SMP shard test
```

A later protocol failure should not trigger speculative loader changes when the earlier milestones are still passing.
