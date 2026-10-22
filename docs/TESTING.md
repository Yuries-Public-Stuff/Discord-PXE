# Hardware validation

This project is validated in layers. Do not skip directly to the experimental SMP shard path when a lower networking or TLS milestone is broken.

The current known-good baseline is a complete **128-shard bring-up in stable BSP scheduler mode**.

## 1. Build and boot

Use the normal repository flow:

```bat
git pull
run.bat
```

`run.bat` rebuilds and refreshes the PXE payload before restarting the PXE server.

Boot the target using legacy network/PXE boot and capture COM1 at:

```text
115200 8N1
```

## 2. Validate the machine/runtime first

A healthy boot should report:

```text
[MODE] x86-64 long mode active
[SMP] processors online=... expected=...
[SMP] multicore worker dispatch verified
[RTL] native polling backend online ...
[IP] address=... router=... dns=...
```

On the currently tested machine the expected CPU count is 4.

If the loader reaches long mode and the native NIC comes online, do not change the PXE loader just because a later TLS or shard operation fails.

## 3. Validate DNS and singleton Discord

Before touching the shard pool, wait for:

```text
[DNS] query sent
[DNS] gateway.discord.gg=...
[TCP] gateway connection established
[X509] leaf chain verified locally
[X509] verified leaf RSA key ready
[TLS] authenticated tls established
[DISCORD] http 101 + websocket accept verified
[DISCORD] READY, bot online
```

This is the control case for the rest of the test.

`shardstart` now refuses to take over Discord transport if DNS is not READY.

## 4. Small isolated shard acceptance

For a short sanity test:

```text
shardtest2
```

This installs a two-shard local plan, takes over from the singleton transport, and starts isolated shard contexts.

After both shards have had time to receive heartbeat acknowledgements:

```text
shardteststatus
```

A full pass prints:

```text
[SHARDTEST] PASS: 2/2 isolated shards READY with TLS + heartbeat ACKs
```

The acceptance path verifies that both shards have separate TCP, TLS, WebSocket, and Discord state.

Reboot to return to the original singleton startup path after a takeover test.

## 5. Full stable 128-shard test

The current hardware-proven path is:

```text
shardplan 128 0 128
shardstart
```

The local plan prints:

```text
[SHARD] local test plan applied; Identify concurrency forced to 1 until /gateway/bot is wired
```

and `shardstart` should print:

```text
[SHARD] singleton Gateway stopped; shard pool owns Discord transport now
[SHARD] shard TCP scheduler enabled (stable BSP mode)
```

The first shard should then progress through:

```text
connection admitted for this Identify wave
tcp start
tcp SYN sent
tcp connected
TLS client key flight + Finished sent
TLS authenticated; WebSocket upgrade sent
HTTP 101 + WebSocket accept verified
Gateway Hello heartbeat-ms=...
Gateway Identify sent
READY, shard online
```

With Identify concurrency 1, connection/Identify bring-up is deliberately staggered.

## 6. Success criteria

For the BSP baseline:

- shard IDs 0 through 127 should each reach READY
- no CPU exception or reset should occur
- the shell/runtime should remain responsive
- transient TCP/TLS failures may enter backoff
- a transient failure is acceptable only if the shard rebuilds and returns to READY
- repeated invalid-session storms are not acceptable

The `shards` command prints current local state and aggregate lifecycle counts.

## 7. Useful commands

```text
shards
shardreset <slot>
shardstop
shardlease <seconds>
```

`shardreset N` rebuilds one local shard slot.

`shardlease 30` is useful for testing controller-style lease expiry. When an armed lease expires, shard-owned traffic is stopped.

## 8. Error interpretation

### `tcp reset by gateway`

A reset is not automatically a runtime failure. If the shard enters backoff, reconnects, and reaches READY again, the reconnect path is functioning.

### `connection failed err=0x00000004 ... tls=0x00000005`

This indicates the shard TLS state entered FAILED. A small number of transient failures have been observed in otherwise successful 128-shard BSP bring-up runs and recovered after backoff.

Repeated widespread failures require investigation.

### `Gateway invalid session`

A storm of invalid-session responses usually indicates bad Identify scheduling or exhausted session-start limits.

Local shell plans force concurrency 1 specifically to avoid guessing Discord's `max_concurrency`.

### DNS starts but never sends

A healthy current build should show both:

```text
[DNS] starting gateway.discord.gg lookup
[DNS] query sent
```

If `query sent` never appears, inspect ARP/TX/DNS state before debugging TLS or sharding.

## 9. TLS-specific debugging

For the complete TLS handshake, runtime key generation, and detailed failure matrix, see [TLS.md](TLS.md).

The important rule is to debug from the **last successful transition**.

### RNG failure

A healthy crypto boot prints:

```text
[RNG] cpu rdrand ready
```

If that is missing or an RNG error is printed, stop there. The runtime intentionally refuses to invent weak TLS randomness.

### TCP succeeds but ClientHello does not

If:

```text
[TCP] gateway connection established
```

appears but:

```text
[TLS] client hello sent
```

does not, inspect RNG readiness, TLS state, TX allocation, and NIC TX availability.

### Certificate chain failure

If TLS records arrive but:

```text
[X509] leaf chain verified locally
```

never appears, inspect record reassembly, DER parsing, issuer trust, and certificate-chain changes.

### Certificate verifies but key exchange authentication fails

If the leaf chain verifies but:

```text
[TLS] pinned certificate + rsa signature verified
```

does not appear, inspect the extracted leaf RSA key and signed ServerKeyExchange input.

### Client key flight is sent but TLS never authenticates

If:

```text
[TLS] client keys + finished sent
```

appears but:

```text
[TLS] authenticated tls established
```

does not, inspect X25519 shared-secret derivation, transcript hashing, PRF seeds/labels, AES-GCM keys/IVs, record sequence numbers, AAD, and Finished verify_data.

### TLS authenticates but WebSocket does not

Once:

```text
[TLS] authenticated tls established
```

appears, the TLS handshake succeeded. Debug HTTP Upgrade/WebSocket framing rather than regenerating TLS trust or key-exchange code.

### SMP-only TLS failures

If stable BSP mode works but enabling AP shard processing causes widespread `tls=0x00000005` failures, suspect shared crypto scratch first.

SHA-256, HMAC/PRF, X25519, AES-GCM, RSA, and X.509/DER contain global temporary workspaces. The experimental SMP path must serialize those sections until they are converted to per-CPU or per-shard scratch.

A failure across many shard IDs is more consistent with shared state than with a single bad Discord certificate.

### Transient TX contention

The native Realtek path uses one TX descriptor. Temporary inability to transmit under concurrent load is not equivalent to a cryptographic failure.

The shard ClientHello path is intended to retry transient TX contention instead of permanently marking TLS failed.

## 10. Experimental SMP validation

Do not use the AP shard scheduler as the first test after unrelated changes.

The intended SMP acceptance progression is:

```text
8
16
32
64
128
```

At each size verify:

- no crypto/TLS corruption
- no CPU faults
- no shard context is processed by multiple workers at once
- all admitted shards eventually reach READY
- heartbeat ACKs continue
- reconnect/backoff still works

The current AP shard scheduler is disabled by default while this validation is pending.

See `docs/STATUS.md` for the current SMP boundary.

## 11. Reporting a hardware run

For a useful failure report, save the entire serial session from boot onward.

The most useful lines include:

- loader markers
- CPU/SMP lines
- native NIC initialization
- IP/router/DNS
- DNS resolution
- first TCP/TLS singleton result
- `shardplan`
- `shardstart`
- first shard failure
- final READY/failure state

Avoid reporting only the final error line; most low-level failures are diagnosed by the transition immediately before it.
