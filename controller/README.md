# Shard controller

This is the first control-plane piece for `discord-pxe-sharded`.

It manages optional cross-node shard leases and node health. The interactive status web UI is served directly by the bare-metal assembly runtime on TCP port 8080.

## Run

```powershell
cd controller
$env:TOTAL_SHARDS = "128"
go run .
```

By default it listens only on:

```text
127.0.0.1:8080
```

Useful environment variables:

- `TOTAL_SHARDS` - global Discord shard count, default 1
- `LEASE_SECONDS` - node lease timeout, default 30
- `LISTEN` - HTTP listen address, default `127.0.0.1:8080`


## Example

```powershell
Invoke-RestMethod http://127.0.0.1:8080/v1/checkin `
  -Method Post `
  -ContentType application/json `
  -Body '{"node_id":"compaq-01","capacity":16}'
```

A second node can check in with another ID. The controller rebalances the global shard set into deterministic contiguous ranges while respecting each node's declared capacity.

Before this is exposed beyond a development machine, the PXE client and controller still need authenticated request signing/TLS plus persistent per-device identity.


## Cross-node Identify gating

Discord's Gateway `max_concurrency` is global to the bot, not per physical PXE machine. Before a node sends an Identify for a shard, the eventual PXE controller client calls:

```json
POST /v1/identify/claim
{
  "node_id": "compaq-01",
  "shard_id": 17
}
```

The controller verifies that the node currently owns the shard and serializes Identify attempts per Discord concurrency bucket. It returns either an immediate grant or a retry delay.

## Guild routing

`GET /v1/route?guild_id=123456789012345678` applies Discord's shard routing formula and returns both the shard ID and the node currently leasing it. This is the control-plane primitive for routing future guild-scoped work to the right bare-metal machine.
