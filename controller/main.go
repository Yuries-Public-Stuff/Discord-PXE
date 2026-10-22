package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxNodeCapacity = 128

type node struct {
	ID             string    `json:"id"`
	Capacity       int       `json:"capacity"`
	Assigned       []int     `json:"assigned"`
	LastSeen       time.Time `json:"last_seen"`
	Generation     uint64    `json:"generation"`
	Draining       bool      `json:"draining"`
	ReadyShards    int       `json:"ready_shards"`
	StartingShards int       `json:"starting_shards"`
	BackoffShards  int       `json:"backoff_shards"`
	FatalShards    int       `json:"fatal_shards"`
}

type checkinRequest struct {
	NodeID         string `json:"node_id"`
	Capacity       int    `json:"capacity"`
	ReadyShards    int    `json:"ready_shards,omitempty"`
	StartingShards int    `json:"starting_shards,omitempty"`
	BackoffShards  int    `json:"backoff_shards,omitempty"`
	FatalShards    int    `json:"fatal_shards,omitempty"`
}

type checkinResponse struct {
	Generation     uint64 `json:"generation"`
	TotalShards    int    `json:"total_shards"`
	Assigned       []int  `json:"assigned"`
	RangeStart     int    `json:"range_start"`
	RangeCount     int    `json:"range_count"`
	LeaseSeconds   int    `json:"lease_seconds"`
	MaxConcurrency int    `json:"max_concurrency"`
}

type controller struct {
	mu             sync.Mutex
	totalShards    int
	maxConcurrency int
	lease          time.Duration
	generation     uint64
	nodes          map[string]*node
	lastIdentify   map[int]time.Time
}

func newController(total, maxConcurrency int, lease time.Duration) *controller {
	return &controller{
		totalShards:    total,
		maxConcurrency: maxConcurrency,
		lease:          lease,
		generation:     1,
		nodes:          make(map[string]*node),
		lastIdentify:   make(map[int]time.Time),
	}
}

func validNodeID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *controller) expireLocked(now time.Time) {
	for id, n := range c.nodes {
		if now.Sub(n.LastSeen) > c.lease {
			delete(c.nodes, id)
		}
	}
}

// rebalancelocked assigns every shard to at most one live node. nodes receive
// deterministic contiguous ranges. range sizes are weighted by
func (c *controller) rebalanceLocked() {
	ids := make([]string, 0, len(c.nodes))
	old := make(map[string][]int, len(c.nodes))
	totalCapacity := 0
	for id, n := range c.nodes {
		ids = append(ids, id)
		old[id] = append([]int(nil), n.Assigned...)
		n.Assigned = n.Assigned[:0]
		if !n.Draining {
			totalCapacity += n.Capacity
		}
	}
	sort.Strings(ids)

	targets := make(map[string]int, len(ids))
	assignedTarget := 0
	if totalCapacity > 0 {
		for _, id := range ids {
			n := c.nodes[id]
			if n.Draining {
				targets[id] = 0
				continue
			}
			want := (c.totalShards * n.Capacity) / totalCapacity
			if want > n.Capacity {
				want = n.Capacity
			}
			targets[id] = want
			assignedTarget += want
		}
	}

	remaining := c.totalShards - assignedTarget
	for remaining > 0 {
		progress := false
		for _, id := range ids {
			n := c.nodes[id]
			if n.Draining || targets[id] >= n.Capacity {
				continue
			}
			targets[id]++
			remaining--
			progress = true
			if remaining == 0 {
				break
			}
		}
		if !progress {
			break
		}
	}

	nextShard := 0
	for _, id := range ids {
		n := c.nodes[id]
		for i := 0; i < targets[id] && nextShard < c.totalShards; i++ {
			n.Assigned = append(n.Assigned, nextShard)
			nextShard++
		}
	}

	changed := false
	for _, id := range ids {
		if !equalInts(old[id], c.nodes[id].Assigned) {
			changed = true
			break
		}
	}
	if changed {
		c.generation++
	}
	for _, n := range c.nodes {
		n.Generation = c.generation
	}
}

func (c *controller) checkin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()

	var req checkinRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !validNodeID(req.NodeID) {
		http.Error(w, "invalid node_id", http.StatusBadRequest)
		return
	}
	if req.Capacity < 1 || req.Capacity > maxNodeCapacity {
		http.Error(w, "capacity must be 1..128", http.StatusBadRequest)
		return
	}
	for _, v := range []int{req.ReadyShards, req.StartingShards, req.BackoffShards, req.FatalShards} {
		if v < 0 || v > maxNodeCapacity {
			http.Error(w, "invalid shard health count", http.StatusBadRequest)
			return
		}
	}

	now := time.Now().UTC()
	c.mu.Lock()
	c.expireLocked(now)
	n := c.nodes[req.NodeID]
	if n == nil {
		n = &node{ID: req.NodeID}
		c.nodes[req.NodeID] = n
	}
	n.Capacity = req.Capacity
	n.ReadyShards = req.ReadyShards
	n.StartingShards = req.StartingShards
	n.BackoffShards = req.BackoffShards
	n.FatalShards = req.FatalShards
	n.LastSeen = now
	c.rebalanceLocked()
	rangeStart := 0
	if len(n.Assigned) > 0 {
		rangeStart = n.Assigned[0]
	}
	resp := checkinResponse{
		Generation:     c.generation,
		TotalShards:    c.totalShards,
		Assigned:       append([]int(nil), n.Assigned...),
		RangeStart:     rangeStart,
		RangeCount:     len(n.Assigned),
		LeaseSeconds:   int(c.lease / time.Second),
		MaxConcurrency: c.maxConcurrency,
	}
	c.mu.Unlock()

	writeJSON(w, resp)
}

func (c *controller) nodesView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	c.mu.Lock()
	c.expireLocked(now)
	c.rebalanceLocked()
	out := make([]node, 0, len(c.nodes))
	for _, n := range c.nodes {
		cp := *n
		cp.Assigned = append([]int(nil), n.Assigned...)
		out = append(out, cp)
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, out)
}

type identifyClaimRequest struct {
	NodeID  string `json:"node_id"`
	ShardID int    `json:"shard_id"`
}

type identifyClaimResponse struct {
	Granted      bool  `json:"granted"`
	Bucket       int   `json:"bucket"`
	RetryAfterMS int64 `json:"retry_after_ms"`
}

func shardForGuild(guildID uint64, totalShards int) int {
	if totalShards <= 0 {
		return 0
	}
	return int((guildID >> 22) % uint64(totalShards))
}

func containsShard(xs []int, shard int) bool {
	for _, x := range xs {
		if x == shard {
			return true
		}
	}
	return false
}

// identifyclaim is the cross-node arbiter for discord's session-start
// max_concurrency buckets. a node must own the shard and receive a grant
func (c *controller) identifyClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	defer r.Body.Close()

	var req identifyClaimRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !validNodeID(req.NodeID) || req.ShardID < 0 {
		http.Error(w, "invalid claim", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	const identifyWindow = 5 * time.Second

	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	c.rebalanceLocked()

	n := c.nodes[req.NodeID]
	if n == nil || !containsShard(n.Assigned, req.ShardID) {
		http.Error(w, "node does not own shard", http.StatusForbidden)
		return
	}
	if req.ShardID >= c.totalShards {
		http.Error(w, "shard out of range", http.StatusBadRequest)
		return
	}

	bucket := req.ShardID % c.maxConcurrency
	last := c.lastIdentify[bucket]
	if !last.IsZero() {
		elapsed := now.Sub(last)
		if elapsed < identifyWindow {
			retry := (identifyWindow - elapsed).Milliseconds()
			writeJSON(w, identifyClaimResponse{
				Granted:      false,
				Bucket:       bucket,
				RetryAfterMS: retry,
			})
			return
		}
	}

	c.lastIdentify[bucket] = now
	writeJSON(w, identifyClaimResponse{
		Granted:      true,
		Bucket:       bucket,
		RetryAfterMS: 0,
	})
}


type drainRequest struct {
	NodeID   string `json:"node_id"`
	Draining bool   `json:"draining"`
}

func (c *controller) drainNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	defer r.Body.Close()

	var req drainRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || !validNodeID(req.NodeID) {
		http.Error(w, "invalid drain request", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	n := c.nodes[req.NodeID]
	if n == nil {
		http.Error(w, "unknown node", http.StatusNotFound)
		return
	}
	n.Draining = req.Draining
	c.rebalanceLocked()
	writeJSON(w, map[string]any{
		"node_id":    n.ID,
		"draining":   n.Draining,
		"generation": c.generation,
		"assigned":   append([]int(nil), n.Assigned...),
	})
}

func (c *controller) statusView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	c.mu.Lock()
	c.expireLocked(now)
	c.rebalanceLocked()
	assigned := 0
	ready := 0
	starting := 0
	backoff := 0
	fatal := 0
	draining := 0
	for _, n := range c.nodes {
		assigned += len(n.Assigned)
		ready += n.ReadyShards
		starting += n.StartingShards
		backoff += n.BackoffShards
		fatal += n.FatalShards
		if n.Draining {
			draining++
		}
	}
	resp := map[string]any{
		"generation":      c.generation,
		"total_shards":    c.totalShards,
		"assigned_shards": assigned,
		"unassigned":      c.totalShards - assigned,
		"ready_shards":    ready,
		"starting_shards": starting,
		"backoff_shards":  backoff,
		"fatal_shards":    fatal,
		"nodes":           len(c.nodes),
		"draining_nodes":  draining,
	}
	c.mu.Unlock()
	writeJSON(w, resp)
}

func (c *controller) configView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	resp := map[string]any{
		"generation":      c.generation,
		"total_shards":    c.totalShards,
		"max_concurrency": c.maxConcurrency,
		"lease_seconds":   int(c.lease / time.Second),
		"node_capacity":   maxNodeCapacity,
	}
	c.mu.Unlock()
	writeJSON(w, resp)
}

func (c *controller) routeView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("guild_id"))
	guildID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		http.Error(w, "invalid guild_id", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	c.mu.Lock()
	c.expireLocked(now)
	c.rebalanceLocked()
	shard := shardForGuild(guildID, c.totalShards)
	owner := ""
	for id, n := range c.nodes {
		if containsShard(n.Assigned, shard) {
			owner = id
			break
		}
	}
	gen := c.generation
	c.mu.Unlock()

	writeJSON(w, map[string]any{
		"guild_id":   raw,
		"shard":      shard,
		"node":       owner,
		"generation": gen,
	})
}

func (c *controller) planView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	c.mu.Lock()
	c.expireLocked(now)
	c.rebalanceLocked()
	type assignment struct {
		Shard int    `json:"shard"`
		Node  string `json:"node"`
	}
	plan := make([]assignment, 0, c.totalShards)
	for id, n := range c.nodes {
		for _, shard := range n.Assigned {
			plan = append(plan, assignment{Shard: shard, Node: id})
		}
	}
	gen := c.generation
	total := c.totalShards
	c.mu.Unlock()

	sort.Slice(plan, func(i, j int) bool { return plan[i].Shard < plan[j].Shard })
	writeJSON(w, map[string]any{
		"generation":   gen,
		"total_shards": total,
		"assignments":  plan,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func envInt(name string, def, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, errors.New(name + " is invalid")
	}
	return n, nil
}

func main() {
	total, err := envInt("TOTAL_SHARDS", 1, 1, 4096)
	if err != nil {
		log.Fatal(err)
	}
	leaseSeconds, err := envInt("LEASE_SECONDS", 30, 5, 3600)
	if err != nil {
		log.Fatal(err)
	}
	maxConcurrency, err := envInt("MAX_CONCURRENCY", 1, 1, 1024)
	if err != nil {
		log.Fatal(err)
	}
	listen := strings.TrimSpace(os.Getenv("LISTEN"))
	if listen == "" {
		listen = "127.0.0.1:8080"
	}

	c := newController(total, maxConcurrency, time.Duration(leaseSeconds)*time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/v1/checkin", c.checkin)
	mux.HandleFunc("/v1/drain", c.drainNode)
	mux.HandleFunc("/v1/status", c.statusView)
	mux.HandleFunc("/v1/identify/claim", c.identifyClaim)
	mux.HandleFunc("/v1/config", c.configView)
	mux.HandleFunc("/v1/nodes", c.nodesView)
	mux.HandleFunc("/v1/plan", c.planView)
	mux.HandleFunc("/v1/route", c.routeView)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("discord-pxe shard controller listening on %s total_shards=%d max_concurrency=%d lease=%ds", listen, total, maxConcurrency, leaseSeconds)
	log.Fatal(srv.ListenAndServe())
}
