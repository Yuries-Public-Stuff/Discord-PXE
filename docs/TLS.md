# TLS, key generation, and debugging

This runtime implements the TLS client path itself. There is no OpenSSL, Schannel, mbedTLS, wolfSSL, libc TLS wrapper, or operating-system certificate store on the target.

The target is a TLS **client** connecting to Discord Gateway. It does **not** need a pre-generated client certificate or long-lived TLS private key.

## What is generated at runtime

Each TLS connection generates fresh ephemeral material on the target.

For every singleton or shard TLS session, the runtime generates:

- a 32-byte TLS ClientRandom
- a fresh 32-byte X25519 private key
- the matching X25519 public key
- an X25519 shared secret using Discord's ephemeral server key
- a TLS 1.2 master secret
- client/server AES-128 keys
- client/server fixed IV material
- record sequence state

The random bytes come from the CPU `RDRAND` instruction through `rng_safe_get`.

If the CPU does not advertise RDRAND support, TLS fails closed instead of using a weak software fallback.

## What is embedded at build time

### Bot credential

If `config/token.txt` exists, the build script embeds the Discord bot token and validated Gateway Identify byte templates into generated runtime data.

Generated secret-bearing files and built runtime images must not be committed to a public repository.

### X.509 trust anchors

The runtime contains public CA trust material in:

```text
src/legacy/legacy_x509_self.inc
```

These are public issuer certificates used to validate the certificate chain sent by Discord.

They are **not private keys** and they do not let the runtime impersonate Discord.

### What is not embedded

The runtime does not embed:

- Discord's leaf certificate
- Discord's RSA private key
- Discord's ephemeral X25519 private key
- a client TLS certificate
- a permanent client TLS private key
- pre-derived TLS traffic keys

Discord sends the live certificate chain and signed ephemeral key-exchange parameters during the TLS handshake.

## TLS handshake used by this runtime

The current implementation follows the hardware-proven TLS 1.2 path used by Discord Gateway.

At a high level:

```text
TCP connected
  |
  v
generate ClientRandom with RDRAND
  |
  v
send TLS 1.2 ClientHello
  |
  v
receive ServerHello
  |
  v
receive certificate chain
  |
  v
validate X.509 chain against built-in trust anchors
  |
  v
extract Discord leaf RSA public key
  |
  v
receive signed X25519 server key
  |
  v
verify RSA/SHA-256 signature over the key exchange
  |
  v
generate fresh client X25519 private key with RDRAND
  |
  v
derive client X25519 public key
  |
  v
compute X25519 shared secret
  |
  v
derive TLS master secret with TLS 1.2 PRF / SHA-256
  |
  v
derive AES-GCM traffic keys + IVs
  |
  v
send ClientKeyExchange
  |
  v
send ChangeCipherSpec + Finished
  |
  v
verify server ChangeCipherSpec + Finished
  |
  v
authenticated TLS application records
  |
  v
WebSocket upgrade
```

The current cipher path is the TLS 1.2 ECDHE_RSA / AES-128-GCM / SHA-256 path selected by the server.

## X25519 key agreement

The client X25519 private key is generated at runtime:

```asm
lea rcx, [r12 + STLS_PRIVATE]
mov edx, 32
call rng_safe_get
```

The public key is derived from that private key:

```asm
lea rcx, [r12 + STLS_PUBLIC]
lea rdx, [r12 + STLS_PRIVATE]
call x25519_public_from_private_x64
```

The shared secret is then computed against the server's X25519 public key:

```asm
lea rcx, [r12 + STLS_SHARED]
lea rdx, [r12 + STLS_PRIVATE]
lea r8,  [r12 + STLS_SERVER_EC]
call x25519_x64
```

An all-zero X25519 shared secret is rejected.

## TLS key schedule

After X25519 produces the shared secret, the runtime derives the TLS 1.2 master secret.

If Extended Master Secret was negotiated, the transcript hash is used as the EMS seed. Otherwise the classic ClientRandom + ServerRandom seed is used.

The runtime then derives the key block with the TLS 1.2 SHA-256 PRF.

For the current AES-128-GCM path, the key block is divided into:

```text
client AES key     16 bytes
server AES key     16 bytes
client fixed IV     4 bytes
server fixed IV     4 bytes
```

Per-record nonces are built from the fixed IV plus the TLS record sequence value.

## Certificate authentication

The runtime does not trust the server merely because a TLS record arrived successfully.

The server certificate path is:

```text
Discord sends certificate chain
  |
  v
DER parser extracts leaf + issuer data
  |
  v
chain validated against built-in CA trust
  |
  v
leaf RSA public key extracted
  |
  v
ServerKeyExchange signature verified
  |
  v
only then is the X25519 server key accepted
```

Useful success markers are:

```text
[X509] leaf chain verified locally
[X509] verified leaf RSA key ready
[TLS] pinned certificate + rsa signature verified
[TLS] client keys + finished sent
[TLS] authenticated tls established
```

The wording `pinned certificate` in legacy log output refers to the authenticated certificate/key path. Current trust is anchored in the built-in issuer trust store; the build no longer discovers certificates from Windows.

## RNG behavior

The RNG initialization checks CPUID for RDRAND support.

A healthy boot prints:

```text
[RNG] cpu rdrand ready
```

If RDRAND is unavailable, the runtime prints an RNG failure and TLS remains unavailable.

There is intentionally no timestamp/counter/pseudo-random fallback for TLS secrets.

## Why TLS can fail

TLS failures are not all certificate failures. The handshake crosses several independent subsystems:

```text
RNG
-> TCP transport
-> TLS record parser
-> X.509 / DER
-> RSA verification
-> X25519
-> SHA-256 / PRF
-> AES-GCM
-> TX/RX sequencing
```

A failure should be diagnosed by the last successful log transition.

## Debugging by last successful marker

### No `[RNG] cpu rdrand ready`

Likely area:

- CPU does not advertise RDRAND
- crypto initialization did not run
- CPU feature state is wrong

TLS cannot safely proceed without a working RNG.

### TCP connects but no TLS ClientHello

Expected sequence:

```text
[TCP] gateway connection established
[TLS] client hello sent
```

If TCP is up but ClientHello never appears, inspect:

- RNG readiness
- TLS state initialization
- TX buffer allocation
- native NIC TX availability

For shards, temporary native-TX contention during ClientHello should now be treated as retryable rather than immediately poisoning the TLS session.

### ClientHello sent, but no server TLS records

Inspect:

- TCP receive path
- TCP sequence/ACK handling
- RX demultiplexing
- MTU/fragment assumptions
- Realtek RX polling

This is usually transport-level, not X.509.

### ServerHello appears, but X.509 verification fails

Inspect:

- certificate record reassembly
- DER lengths
- leaf/issuer extraction
- trusted issuer set
- RSA public-key extraction
- certificate validity/chain changes

The trust store is deliberately explicit. If Discord changes to a certificate chain outside the currently trusted issuer set, the runtime should fail rather than silently accept it.

### `leaf chain verified locally` appears, but signed key verification fails

Inspect:

- extracted leaf RSA public key
- ServerKeyExchange parsing
- ClientRandom/ServerRandom values used in the signed input
- X25519 parameter bytes
- RSA/SHA-256 verification

This means certificate-chain validation succeeded but authentication of the ephemeral key exchange did not.

### X25519 or key derivation fails

Inspect:

- RDRAND output path
- private/public X25519 buffers
- server ephemeral key
- all-zero shared-secret rejection
- transcript contents
- Extended Master Secret state
- SHA-256 / PRF workspace

### Client key flight is sent, but server Finished never authenticates

Inspect:

- master-secret derivation
- PRF labels and seeds
- transcript hash
- key-block split
- TLS record sequence numbers
- AES-GCM nonce construction
- AAD
- Finished verify_data

This is one of the strongest signs of a key-schedule or record-crypto mismatch.

### TLS authenticates, but WebSocket fails

Once this appears:

```text
[TLS] authenticated tls established
```

the TLS handshake itself succeeded.

Debug:

- encrypted application-record framing
- HTTP Upgrade request
- WebSocket Accept verification
- WebSocket frame parser

Do not go back and change X.509 or X25519 without evidence.

### `connection failed err=0x00000004 ... tls=0x00000005`

This means the shard TLS state entered FAILED.

Possible causes include:

- real TLS parser/authentication failure
- record crypto failure
- transport failure promoted into TLS failure
- shared crypto scratch corruption under experimental SMP execution

A small number of transient failures have recovered successfully in stable BSP 128-shard runs. A widespread burst across many shards is not normal and should be treated as a systemic bug.

## SMP-specific TLS failure mode

The high-level shard TLS contexts are private per shard, but several low-level crypto implementations still use global scratch memory.

Known shared scratch exists in code paths for:

- SHA-256
- HMAC
- TLS PRF
- X25519
- AES-GCM
- RSA
- X.509/DER

That means two CPUs cannot safely execute those primitives concurrently unless the shared scratch is protected.

The first experimental multithreaded shard run produced widespread TLS failures because separate APs were executing crypto at the same time and overwriting shared temporary state.

The current experimental SMP path therefore serializes non-reentrant crypto work with a global crypto lock.

This does **not** mean shards intentionally share keys. Their session keys remain separate. The lock protects temporary implementation workspace.

Long term, better designs include:

- per-CPU crypto scratch
- per-shard crypto scratch
- a dedicated serialized crypto service

## Native TX contention

The tested Realtek backend uses a single native TX descriptor.

Under concurrent shard execution, temporary TX contention is possible.

A transient inability to send a ClientHello should not be treated as proof that the TLS cryptography is invalid. The shard ClientHello path now leaves TLS in an idle/retryable state for temporary TX failure.

When debugging SMP TLS failures, distinguish:

```text
could not transmit yet
```

from:

```text
transmitted record, peer rejected/decryption failed
```

They are different bugs.

## Shard-specific TLS state

Each shard has private high-level storage for:

- ClientRandom
- ServerRandom
- X25519 private/public/shared values
- transcript
- master secret
- key block
- client/server AES keys
- IVs
- record sequence counters
- handshake buffers
- record buffers

This isolation is why 128 separate TLS sessions can coexist in stable BSP mode.

## Security notes

The TLS implementation is purpose-built and experimental.

Important consequences:

- generated binaries containing the bot token are secret
- TLS correctness depends on custom crypto and parser code
- the issuer trust store must be maintained deliberately
- the project has a much smaller interoperability surface than a general TLS library
- successful operation against Discord does not imply general TLS compliance
- experimental SMP crypto must not be considered safe until the hardware validation sequence passes

For current proven status, see [STATUS.md](STATUS.md).

For hardware debugging, see [TESTING.md](TESTING.md).
