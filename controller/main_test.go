package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRebalanceContiguousAndUnique(t *testing.T) {
	c := newController(32, 4, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 8, LastSeen: now}
	c.nodes["node-b"] = &node{ID: "node-b", Capacity: 24, LastSeen: now}

	c.rebalanceLocked()

	if got := len(c.nodes["node-a"].Assigned); got != 8 {
		t.Fatalf("node-a got %d shards, want 8", got)
	}
	if got := len(c.nodes["node-b"].Assigned); got != 24 {
		t.Fatalf("node-b got %d shards, want 24", got)
	}

	seen := make(map[int]string)
	for id, n := range c.nodes {
		for i, shard := range n.Assigned {
			if owner, ok := seen[shard]; ok {
				t.Fatalf("shard %d assigned twice: %s and %s", shard, owner, id)
			}
			seen[shard] = id
			if i > 0 && n.Assigned[i-1]+1 != shard {
				t.Fatalf("%s range is not contiguous: %v", id, n.Assigned)
			}
		}
	}
	if len(seen) != 32 {
		t.Fatalf("assigned %d shards, want 32", len(seen))
	}
}

func TestCapacityShortfallLeavesUnassigned(t *testing.T) {
	c := newController(128, 1, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 16, LastSeen: now}
	c.nodes["node-b"] = &node{ID: "node-b", Capacity: 16, LastSeen: now}
	c.rebalanceLocked()

	total := len(c.nodes["node-a"].Assigned) + len(c.nodes["node-b"].Assigned)
	if total != 32 {
		t.Fatalf("assigned %d shards, want capacity-limited 32", total)
	}
}

func TestExpiredNodeRebalances(t *testing.T) {
	c := newController(16, 2, 10*time.Second)
	now := time.Now().UTC()
	c.nodes["dead"] = &node{ID: "dead", Capacity: 8, LastSeen: now.Add(-time.Minute)}
	c.nodes["live"] = &node{ID: "live", Capacity: 16, LastSeen: now}
	c.rebalanceLocked()
	before := c.generation

	c.expireLocked(now)
	c.rebalanceLocked()

	if _, ok := c.nodes["dead"]; ok {
		t.Fatal("expired node still present")
	}
	if got := len(c.nodes["live"].Assigned); got != 16 {
		t.Fatalf("live node got %d shards after failover, want 16", got)
	}
	if c.generation <= before {
		t.Fatalf("generation did not advance: before=%d after=%d", before, c.generation)
	}
}

func TestStablePlanDoesNotBumpGeneration(t *testing.T) {
	c := newController(8, 1, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 8, LastSeen: now}
	c.rebalanceLocked()
	gen := c.generation
	c.rebalanceLocked()
	if c.generation != gen {
		t.Fatalf("stable plan changed generation: %d -> %d", gen, c.generation)
	}
}

func TestValidNodeID(t *testing.T) {
	good := []string{"compaq-01", "rack_a.7", "A1"}
	for _, s := range good {
		if !validNodeID(s) {
			t.Fatalf("expected valid node id %q", s)
		}
	}
	bad := []string{"", "two words", "../node", "node/1", "x:y"}
	for _, s := range bad {
		if validNodeID(s) {
			t.Fatalf("expected invalid node id %q", s)
		}
	}
}


func TestIdentifyBucketGrantAcrossNodes(t *testing.T) {
	c := newController(8, 2, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 4, LastSeen: now}
	c.nodes["node-b"] = &node{ID: "node-b", Capacity: 4, LastSeen: now}
	c.rebalanceLocked()

	// shards 0 and 2 share concurrency bucket 0 when max_concurrency=2.
	if !containsShard(c.nodes["node-a"].Assigned, 0) {
		t.Fatalf("node-a plan unexpected: %v", c.nodes["node-a"].Assigned)
	}
	if !containsShard(c.nodes["node-a"].Assigned, 2) {
		t.Fatalf("node-a plan unexpected: %v", c.nodes["node-a"].Assigned)
	}

	bucket := 0 % c.maxConcurrency
	c.lastIdentify[bucket] = now
	if elapsed := now.Sub(c.lastIdentify[2%c.maxConcurrency]); elapsed >= 5*time.Second {
		t.Fatal("same bucket unexpectedly eligible immediately")
	}

	// a different bucket is independent.
	if _, exists := c.lastIdentify[1%c.maxConcurrency]; exists {
		t.Fatal("different identify bucket should be free")
	}
}

func TestIdentifyOwnershipHelpers(t *testing.T) {
	if !containsShard([]int{4, 5, 6}, 5) {
		t.Fatal("expected shard membership")
	}
	if containsShard([]int{4, 5, 6}, 7) {
		t.Fatal("unexpected shard membership")
	}
}


func TestShardForGuild(t *testing.T) {
	const guild uint64 = 123456789012345678
	got := shardForGuild(guild, 128)
	want := int((guild >> 22) % 128)
	if got != want {
		t.Fatalf("shardForGuild=%d want=%d", got, want)
	}
	if shardForGuild(guild, 1) != 0 {
		t.Fatal("single-shard bot must always route to shard 0")
	}
}

func TestDrainMovesShardsAway(t *testing.T) {
	c := newController(16, 2, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 8, LastSeen: now}
	c.nodes["node-b"] = &node{ID: "node-b", Capacity: 16, LastSeen: now}
	c.rebalanceLocked()

	if len(c.nodes["node-a"].Assigned) == 0 {
		t.Fatal("node-a should initially own shards")
	}
	before := c.generation
	c.nodes["node-a"].Draining = true
	c.rebalanceLocked()

	if got := len(c.nodes["node-a"].Assigned); got != 0 {
		t.Fatalf("draining node still owns %d shards: %v", got, c.nodes["node-a"].Assigned)
	}
	if got := len(c.nodes["node-b"].Assigned); got != 16 {
		t.Fatalf("node-b got %d shards after drain, want 16", got)
	}
	if c.generation <= before {
		t.Fatalf("drain did not advance generation: %d -> %d", before, c.generation)
	}
}

func TestHundredTwentyEightAcrossEightNodes(t *testing.T) {
	c := newController(128, 16, 30*time.Second)
	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		id := "node-" + string(rune('a'+i))
		c.nodes[id] = &node{ID: id, Capacity: 16, LastSeen: now}
	}
	c.rebalanceLocked()

	seen := make(map[int]string)
	for id, n := range c.nodes {
		if got := len(n.Assigned); got != 16 {
			t.Fatalf("%s got %d shards, want 16", id, got)
		}
		for i, shard := range n.Assigned {
			if old, ok := seen[shard]; ok {
				t.Fatalf("shard %d duplicated on %s and %s", shard, old, id)
			}
			seen[shard] = id
			if i > 0 && n.Assigned[i-1]+1 != shard {
				t.Fatalf("%s assignment not contiguous: %v", id, n.Assigned)
			}
		}
	}
	if len(seen) != 128 {
		t.Fatalf("covered %d shards, want 128", len(seen))
	}
}

func TestHealthCountsDoNotAffectOwnership(t *testing.T) {
	c := newController(8, 2, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{
		ID: "node-a", Capacity: 8, LastSeen: now,
		ReadyShards: 4, StartingShards: 2, BackoffShards: 1, FatalShards: 1,
	}
	c.rebalanceLocked()
	if got := len(c.nodes["node-a"].Assigned); got != 8 {
		t.Fatalf("health reporting changed assignment: got %d", got)
	}
}

func TestIdentifyClaimHTTP(t *testing.T) {
	c := newController(4, 2, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 4, LastSeen: now}
	c.rebalanceLocked()

	body := []byte(`{"node_id":"node-a","shard_id":0}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/identify/claim", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	c.identifyClaim(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first claim status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first identifyClaimResponse
	if err := json.NewDecoder(rec.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	if !first.Granted || first.Bucket != 0 {
		t.Fatalf("unexpected first claim: %+v", first)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/identify/claim", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	c.identifyClaim(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second claim status=%d body=%s", rec.Code, rec.Body.String())
	}
	var second identifyClaimResponse
	if err := json.NewDecoder(rec.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if second.Granted || second.RetryAfterMS <= 0 {
		t.Fatalf("same bucket was not rate limited: %+v", second)
	}
}

func TestDrainHTTP(t *testing.T) {
	c := newController(8, 2, 30*time.Second)
	now := time.Now().UTC()
	c.nodes["node-a"] = &node{ID: "node-a", Capacity: 4, LastSeen: now}
	c.nodes["node-b"] = &node{ID: "node-b", Capacity: 8, LastSeen: now}
	c.rebalanceLocked()

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/drain",
		bytes.NewBufferString(`{"node_id":"node-a","draining":true}`),
	)
	rec := httptest.NewRecorder()
	c.drainNode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("drain status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !c.nodes["node-a"].Draining {
		t.Fatal("node-a was not marked draining")
	}
	if len(c.nodes["node-a"].Assigned) != 0 {
		t.Fatalf("draining node still owns shards: %v", c.nodes["node-a"].Assigned)
	}
	if len(c.nodes["node-b"].Assigned) != 8 {
		t.Fatalf("node-b did not absorb shards: %v", c.nodes["node-b"].Assigned)
	}
}
