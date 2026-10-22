# discord-pxe-sharded

A bare-metal x86-64 Discord Gateway client that boots over **legacy BIOS PXE**, drives a **Realtek NIC directly**, implements its own IPv4/TCP/TLS/WebSocket stack, and can run up to **128 local Discord Gateway shard contexts** on one physical machine.

There is no Linux, Windows, libc, OpenSSL, curl, Node.js, or Discord SDK on the target. The runtime is primarily NASM assembly and talks to the hardware and Discord Gateway itself.

> This is an experimental systems project, not a production Discord library.

## What is hardware-proven

The current `main` branch has been exercised on real x86 hardware with:

- legacy BIOS PXE boot and TFTP runtime loading
- x86-64 long-mode transition
- 4 logical CPUs brought online through the SMP runtime
- native Realtek network I/O
- DHCP-derived IPv4, router, and DNS configuration
- DNS resolution of `gateway.discord.gg`
- TCP to Discord Gateway
- TLS 1.2 with local X.509 chain verification
- WebSocket upgrade
- Discord Gateway Hello / Identify / READY
- a local pool of **128 shard contexts**
- a complete **128-shard READY bring-up** in stable BSP scheduler mode
- per-shard reconnect/backoff after transient TCP/TLS failures

The SMP worker system itself is also hardware-proven. Actual shard state-machine execution on AP workers exists in the tree, but is currently **disabled by default** while the shared crypto path is being made safely re-entrant/serialized.

See [docs/STATUS.md](docs/STATUS.md) for the exact current boundary between proven and experimental behavior.

## Boot flow

```text
BIOS PXE
  -> stage1.pxe
  -> PXENV+ / DHCP / TFTP
  -> runtime.bin at physical 0x20000
  -> E820 + page tables
  -> x86-64 long mode
  -> SMP bring-up
  -> native Realtek networking
  -> DNS / TCP / TLS / WebSocket
  -> Discord Gateway
  -> singleton or shard pool
```

The stage-1 loader temporarily protects the PXE firmware stack while the runtime image crosses the firmware's low-memory stack region, then restores the runtime after TFTP is closed.

## Requirements

Build host:

- Windows
- PowerShell
- NASM available either on `PATH` or in the standard Program Files NASM directory
- a working PXE/TFTP setup supported by the repository tooling

Target:

- legacy BIOS/CSM PXE boot
- x86-64 CPU
- supported Realtek NIC for the native runtime path
- serial output is strongly recommended for diagnostics

## Configure the bot token

Create:

```text
config/token.txt
```

with the Discord bot token. A leading `Bot ` prefix is accepted and normalized by the build script.

The token is converted into validated Gateway Identify bytes at build time and embedded into the generated runtime include. Do not commit the token file.

The current sharded Identify payload uses `intents: 0`.

## Build

```bat
build.bat
```

This produces:

```text
build\stage1.pxe
build\runtime.bin
```

The build script validates image sizes and prints SHA-256 hashes for both outputs.

## Build, install PXE files, and boot

The normal hardware flow is:

```bat
git pull
run.bat
```

`run.bat` invokes `tools\setup-pxe.ps1`, builds the current tree, installs the generated PXE files, updates the PXE configuration, and restarts the PXE server.

Then boot the target using legacy network/PXE boot.

Serial diagnostics are emitted at **115200 8N1**.

## Expected singleton milestone

Before starting the shard pool, a healthy boot should reach roughly:

```text
[DNS] query sent
[DNS] gateway.discord.gg=...
[TCP] gateway connection established
[X509] leaf chain verified locally
[TLS] authenticated tls established
[DISCORD] http 101 + websocket accept verified
[DISCORD] READY, bot online
```

If that path is not healthy, do not debug sharding first.

## Start the 128-shard local test

At the runtime shell:

```text
shardplan 128 0 128
shardstart
```

Local shell plans intentionally force Discord Identify concurrency to `1` until `/gateway/bot` discovery is wired into the runtime.

A normal shard progresses through:

```text
connection admitted
tcp start
tcp SYN sent
tcp connected
TLS client key flight + Finished sent
TLS authenticated; WebSocket upgrade sent
HTTP 101 + WebSocket accept verified
Gateway Hello
Gateway Identify sent
READY, shard online
```

Useful shell commands include:

```text
shards
shardplan <total> <start> <count>
shardstart
shardstop
shardreset <slot>
shardlease <seconds>
shardtest2
shardteststatus
```

See [docs/TESTING.md](docs/TESTING.md) for the hardware validation sequence.

## Why Identify concurrency is forced to 1

Discord's shard Identify concurrency is not a number that should be guessed from CPU count or supplied arbitrarily by a local shell command. It comes from the bot's `/gateway/bot` response.

Until that REST path is implemented, local plans use the conservative value `1`. This avoids the invalid-session storm that occurred when local tests previously used arbitrary concurrency values.

## SMP status

The runtime brings all detected logical CPUs online and has a working AP job dispatcher.

There is also an SMP shard scheduler that stripes shard contexts across AP workers. That path is currently off by default because the crypto implementation contains global scratch workspaces used by SHA-256, HMAC/PRF, X25519, AES-GCM, RSA, and X.509 operations.

The current experimental SMP design therefore:

- runs lifecycle/TCP work on disjoint shard contexts
- serializes non-reentrant crypto sections
- serializes shared network transmit construction
- falls back to BSP processing if AP dispatch fails

That corrected path still requires hardware validation before becoming the default.

## Repository map

```text
src/stage1/                 PXE stage-1 loader
src/legacy/                 x86-64 runtime and protocol stack
controller/                 experimental multi-node shard controller
tools/                      build and PXE setup scripts
config/                     local runtime configuration inputs
docs/ARCHITECTURE.md        runtime architecture and ownership boundaries
docs/STATUS.md              current proven/experimental status
docs/SHARDING.md            sharding design and remaining milestones
docs/TESTING.md             hardware validation procedure
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [TLS, key generation, and debugging](docs/TLS.md)
- [Current hardware status](docs/STATUS.md)
- [Sharding design](docs/SHARDING.md)
- [Hardware testing](docs/TESTING.md)

## Security and protocol notes

This project intentionally keeps its normal-account proof-of-concept credential path outbound-disabled. The live Discord transport uses the bot token only.

The runtime currently embeds its bot credential into the built image. Treat generated PXE binaries as secrets if they were built with a real token.

TLS/X.509 is implemented locally in the runtime. ClientRandom values and ephemeral X25519 private keys are generated on-target from CPU RDRAND for each connection; no client TLS certificate or permanent TLS private key is pre-generated. See [docs/TLS.md](docs/TLS.md) for the key schedule and failure diagnostics.

This project should therefore be treated as research/experimental software rather than a replacement for a maintained general-purpose TLS stack.

## License

Use the repository's existing license terms, if present.
