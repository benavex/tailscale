// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"time"

	"tailscale.com/ipn"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

// meshFailover tracks sibling control servers advertised via the
// benavex.com/cap/mesh CapMap entry and rotates [ipn.Prefs.ControlURL]
// away from a dead primary after
// [meshFailoverFailureThreshold] of uninterrupted failure.
//
// Lives on LocalBackend; all fields guarded by LocalBackend.mu.
type meshFailover struct {
	// peers is the current sibling list from the last netmap that
	// carried the mesh cap. Order is preserved from the server so
	// every client rotates through the same sequence.
	peers []nmcfg.MeshPeer

	// lastOK is the wall-clock time of the most recent successful
	// control message (netmap received). Zero until first success.
	lastOK time.Time

	// failureStart is when the current streak of control failures
	// began. Zero when there is no current streak.
	failureStart time.Time

	// rotateIdx is the index of the next peer to try on rotation.
	// Modulo len(peers).
	rotateIdx int

	// rotating guards against re-entrant rotations (EditPrefs runs
	// without the big mu, so a slow rotate could race a probe).
	rotating bool
}

// meshFailoverFailureThreshold is how long control must be broken before
// we rotate. Short enough that a real outage gets failover quickly,
// long enough that transient blips don't thrash the ControlURL.
const meshFailoverFailureThreshold = 60 * time.Second

// meshFailoverProbeInterval is how often the watchdog wakes. Keep
// below meshFailoverFailureThreshold/2 so rotation fires promptly
// after the threshold elapses.
const meshFailoverProbeInterval = 20 * time.Second

// updateMeshFromNetmapLocked extracts the mesh snapshot from nm (if
// any) and refreshes b.meshFailover.peers. Also records lastOK because
// arrival of any netmap is proof that the current control server is
// alive.
//
// b.mu must be held.
func (b *LocalBackend) updateMeshFromNetmapLocked(nm *netmap.NetworkMap) {
	b.meshFailover.lastOK = time.Now()
	b.meshFailover.failureStart = time.Time{}

	snap, ok := nmcfg.ExtractMesh(nm)
	if !ok {
		// Single-server install (or server doesn't publish cap).
		// Keep any previously-known peers — they're still our best
		// guess during a server reboot — but don't zero them out.
		return
	}
	b.meshFailover.peers = append(b.meshFailover.peers[:0], snap.Peers...)
}

// noteControlFailureLocked records that the control connection just
// failed. Idempotent while a failure streak is ongoing.
//
// b.mu must be held.
func (b *LocalBackend) noteControlFailureLocked() {
	if b.meshFailover.failureStart.IsZero() {
		b.meshFailover.failureStart = time.Now()
	}
}

// maybeFailoverControlURL runs the rotation decision. Call periodically
// from a background goroutine; NOT under b.mu — it acquires the lock
// itself and may call EditPrefs.
func (b *LocalBackend) maybeFailoverControlURL() {
	b.mu.Lock()
	mf := &b.meshFailover
	if mf.rotating || mf.failureStart.IsZero() ||
		time.Since(mf.failureStart) < meshFailoverFailureThreshold ||
		len(mf.peers) == 0 {
		b.mu.Unlock()
		return
	}

	// Pick next online peer. If none of the snapshot entries are
	// marked online, stay on the current URL — we have no evidence
	// that any alternative is better, and rotating to a known-dead
	// peer just stretches the outage.
	var target nmcfg.MeshPeer
	for i := 0; i < len(mf.peers); i++ {
		candidate := mf.peers[(mf.rotateIdx+i)%len(mf.peers)]
		if candidate.URL == "" || !candidate.Online {
			continue
		}
		target = candidate
		mf.rotateIdx = (mf.rotateIdx + i + 1) % len(mf.peers)
		break
	}
	if target.URL == "" {
		b.logf("mesh: no online peer to rotate to; staying on %q", b.pm.CurrentPrefs().ControlURL())
		b.mu.Unlock()
		return
	}

	currentURL := b.pm.CurrentPrefs().ControlURL()
	if target.URL == currentURL {
		// Nothing to do — already on this server.
		b.mu.Unlock()
		return
	}
	mf.rotating = true
	b.mu.Unlock()

	b.logf("mesh: control URL %q unresponsive for %v; rotating to %q (%s)",
		currentURL, meshFailoverFailureThreshold, target.URL, target.Name)

	_, err := b.EditPrefs(&ipn.MaskedPrefs{
		ControlURLSet: true,
		Prefs: ipn.Prefs{
			ControlURL: target.URL,
		},
	})
	if err != nil {
		b.logf("mesh: failover EditPrefs failed: %v", err)
	}

	// Force a full restart so the new ControlURL takes effect. EditPrefs
	// alone does not reset the control client (documented at
	// ipn/prefs.go ControlURL field).
	b.mu.Lock()
	old := b.resetControlClientLocked()
	b.mu.Unlock()
	if old != nil {
		old.Shutdown()
	}
	if err := b.Start(ipn.Options{}); err != nil {
		b.logf("mesh: failover Start failed: %v", err)
	}

	b.mu.Lock()
	b.meshFailover.rotating = false
	// Reset failure timer; if the new server is also dead, we'll
	// rotate again after the next threshold window.
	b.meshFailover.failureStart = time.Time{}
	b.mu.Unlock()
}

// runMeshFailoverWatchdog is the background loop that drives rotation.
// Started once per LocalBackend; exits when b.ctx is cancelled.
func (b *LocalBackend) runMeshFailoverWatchdog() {
	// Lazy singleton: don't spawn the goroutine twice if Start is
	// re-entered after a failover-triggered restart.
	b.meshWatchdogOnce.Do(func() {
		b.goTracker.Go(func() {
			t := time.NewTicker(meshFailoverProbeInterval)
			defer t.Stop()
			for {
				select {
				case <-b.ctx.Done():
					return
				case <-t.C:
					b.maybeFailoverControlURL()
				}
			}
		})
	})
}
