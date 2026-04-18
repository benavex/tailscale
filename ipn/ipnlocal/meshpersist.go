// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// On-disk persistence for mesh failover state.
//
// Why: meshFailover.peers lives only in volatile memory and is
// populated only from incoming netmaps. When a phone (or any client)
// wakes up bound to a dead ControlURL, it never receives a netmap and
// the watchdog has an empty peer list — maybeFailoverControlURL
// early-returns and the client stays stuck on the dead primary
// indefinitely. This is mode A of I-02 reproduced 2026-04-18.
//
// Persisting the last-known peers + self + crown to disk lets the
// watchdog rotate on the very first connection attempt after a cold
// start, even when the bound primary never responds.

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/wgengine/wgcfg/nmcfg"
)

// meshStateFile lives directly under varRoot, alongside clusterpin.json.
// One file per machine — rotating user accounts must not lose the
// failover topology.
const meshStateFile = "meshstate.json"

// persistedMeshState is the on-disk record. Mirror of the live
// meshFailover fields that are useful at startup before any netmap
// arrives. failureStart / lastOK / rotateIdx are deliberately omitted
// — they reset cleanly on every cold start.
type persistedMeshState struct {
	Peers   []nmcfg.MeshPeer `json:"peers"`
	Self    nmcfg.MeshPeer   `json:"self"`
	Crown   string           `json:"crown"`
	SavedAt time.Time        `json:"saved_at"`
}

// meshStatePath returns the absolute path of the mesh state file for
// this backend, or "" when no var root is configured (e.g. in tests
// without SetVarRoot). Callers should skip persistence when "".
func (b *LocalBackend) meshStatePath() string {
	root := b.TailscaleVarRoot()
	if root == "" {
		return ""
	}
	return filepath.Join(root, meshStateFile)
}

// loadPersistedMeshState reads the file and returns the parsed state,
// or (nil, nil) when no file exists yet. Returns (nil, err) for
// genuine I/O or parse errors so the caller can log and continue
// (failure to load is non-fatal — we just won't have a peer list
// until the first netmap lands).
func (b *LocalBackend) loadPersistedMeshState() (*persistedMeshState, error) {
	path := b.meshStatePath()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read mesh state: %w", err)
	}
	var st persistedMeshState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse mesh state: %w", err)
	}
	return &st, nil
}

// savePersistedMeshState writes the current peers+self+crown to disk
// atomically (write-temp-then-rename). Errors are logged but not
// returned — persistence is best-effort; a write failure should not
// crash the watchdog.
//
// b.mu may be held by the caller, so this function does no locking
// itself; the caller is responsible for snapshotting the fields it
// passes in.
func (b *LocalBackend) savePersistedMeshState(peers []nmcfg.MeshPeer, self nmcfg.MeshPeer, crown string) {
	path := b.meshStatePath()
	if path == "" {
		return
	}
	st := persistedMeshState{
		Peers:   peers,
		Self:    self,
		Crown:   crown,
		SavedAt: time.Now(),
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		b.logf("mesh: persisted state marshal failed: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.logf("mesh: persisted state mkdir failed: %v", err)
		return
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		b.logf("mesh: persisted state write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		b.logf("mesh: persisted state rename failed: %v", err)
		return
	}
}

// hydrateMeshFromDisk fills b.meshFailover from the on-disk record if
// one exists and the in-memory peer list is currently empty (i.e.
// pre-first-netmap). Idempotent: a no-op when peers are already
// populated, so a stale persisted file doesn't override fresh netmap
// data.
//
// b.mu must be held by the caller. Currently only called from
// runMeshFailoverWatchdog, which itself runs under startLocked's lock.
func (b *LocalBackend) hydrateMeshFromDisk() {
	if len(b.meshFailover.peers) > 0 {
		return
	}
	st, err := b.loadPersistedMeshState()
	if err != nil {
		b.logf("mesh: persisted state load failed (continuing without it): %v", err)
		return
	}
	if st == nil {
		return
	}
	b.meshFailover.peers = append(b.meshFailover.peers[:0], st.Peers...)
	b.meshFailover.self = st.Self
	b.meshFailover.crown = st.Crown
	b.logf("mesh: restored %d peer(s) + crown=%q from disk (saved %v ago)",
		len(st.Peers), st.Crown, time.Since(st.SavedAt).Round(time.Second))
}

// errMeshStateNotPersistable is returned when persistence is impossible
// (no var root). Callers can treat this as "skip silently".
var errMeshStateNotPersistable = errors.New("no var root configured for mesh state")
