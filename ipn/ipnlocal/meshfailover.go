// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
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

	// self is the local headscale's snapshot entry from the last
	// netmap. Tracked alongside peers so the follow-crown logic can
	// resolve a crown that points back at "self".
	self nmcfg.MeshPeer

	// crown is the name of the currently-elected crown headscale,
	// taken from the most recent mesh CapMap snapshot. Empty until
	// the first netmap with a snapshot lands.
	crown string

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
	b.meshFailover.self = snap.Self

	// Snapshot crown change before we drop the lock so the rotation
	// goroutine sees the new value. Don't fire EditPrefs from under
	// b.mu — defer to the watchdog tick.
	if snap.Crown != b.meshFailover.crown {
		b.meshFailover.crown = snap.Crown
	}
}

// crownExitNodeFromMeshLocked returns the ExitNodeName the current
// crown advertises in the mesh snapshot. Empty when no crown is set,
// no matching peer entry, or the operator hasn't configured exit_node_name
// on that headscale.
//
// b.mu must be held (read).
func (b *meshFailover) crownExitNodeFromMeshLocked() string {
	if b.crown == "" {
		return ""
	}
	if b.self.Name == b.crown {
		return b.self.ExitNodeName
	}
	for _, p := range b.peers {
		if p.Name == b.crown {
			return p.ExitNodeName
		}
	}
	return ""
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
	//
	// When the peer carries a cluster signature (server side has
	// identity pinning configured), require it to verify against our
	// pinned cluster key before accepting it as a rotation target. A
	// peer that fails verification is skipped even if marked online;
	// better to sit on an unreachable primary than fail over to an
	// attacker-run sibling. When no pin exists and no peer carries a
	// signature, rotation still works (legacy mode); when a pin exists
	// but a candidate carries no signature, we refuse it.
	// Pin-state corruption must fail CLOSED, not open. If a pin file
	// exists but is unreadable or malformed, we cannot tell whether
	// verification would have passed — so we refuse to rotate at all
	// and let the operator fix the file. Only a genuinely absent pin
	// file (nil, nil) allows legacy unpinned rotation.
	pin, pinErr := b.loadClusterPin()
	if pinErr != nil {
		b.logf("mesh: cluster pin file corrupt (%v); refusing to rotate — fix or delete %s",
			pinErr, b.clusterPinPath())
		b.mu.Unlock()
		return
	}
	pinPresent := pin != nil
	var target nmcfg.MeshPeer
	var skipped int
	for i := 0; i < len(mf.peers); i++ {
		candidate := mf.peers[(mf.rotateIdx+i)%len(mf.peers)]
		if candidate.URL == "" || !candidate.Online {
			continue
		}
		if pinPresent {
			if err := b.verifyPeerAgainstPin(candidate); err != nil {
				b.logf("mesh: refusing rotation to %q (%s): %v",
					candidate.URL, candidate.Name, err)
				skipped++
				continue
			}
		}
		target = candidate
		mf.rotateIdx = (mf.rotateIdx + i + 1) % len(mf.peers)
		break
	}
	if target.URL == "" {
		b.logf("mesh: no eligible peer to rotate to (skipped %d unverified); staying on %q",
			skipped, b.pm.CurrentPrefs().ControlURL())
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

// maybeFollowCrownExitNode pins ExitNodeID to the crown's
// declared exit-node when prefs.AutoExitNode == "follow-crown".
//
// Called from updateMeshFromNetmapLocked (so it fires the moment a new
// crown lands in a netmap) and from the watchdog tick (so it converges
// even if the netmap arrived during a rotation). Idempotent: bails out
// when the desired ExitNodeID already matches.
//
// NOT under b.mu — uses EditPrefs which acquires the lock itself.
func (b *LocalBackend) maybeFollowCrownExitNode() {
	prefs := b.pm.CurrentPrefs()
	if prefs.AutoExitNode() != ipn.FollowCrownExitNode {
		return
	}

	b.mu.Lock()
	exitName := b.meshFailover.crownExitNodeFromMeshLocked()
	nm := b.netMap
	b.mu.Unlock()

	if exitName == "" || nm == nil {
		// Crown has no exit_node_name configured, or no netmap yet.
		// Keep whatever was last set so a missing-config blip doesn't
		// blackhole egress.
		return
	}

	// Resolve the tailnet hostname → StableNodeID. tailcfg.Node.Name is
	// the FQDN ("exit-vps1.benavex.hs-test.local."), so match by the
	// label before the first dot, or by Hostinfo().Hostname() exactly.
	var target tailcfg.StableNodeID
	for _, peer := range nm.Peers {
		if peer.Hostinfo().Hostname() == exitName {
			target = peer.StableID()
			break
		}
		name := peer.Name()
		if i := strings.IndexByte(name, '.'); i > 0 {
			name = name[:i]
		}
		if name == exitName {
			target = peer.StableID()
			break
		}
	}
	if target.IsZero() {
		// Crown's declared exit node isn't in our netmap (yet?).
		// Wait for the next netmap cycle rather than churning Prefs.
		return
	}
	if prefs.ExitNodeID() == target {
		return
	}

	b.logf("mesh: follow-crown rotating exit node to %q (crown=%q)", exitName, b.meshFailover.crown)
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{
		ExitNodeIDSet: true,
		Prefs: ipn.Prefs{
			ExitNodeID: target,
		},
	}); err != nil {
		b.logf("mesh: follow-crown EditPrefs failed: %v", err)
	}
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
					b.maybeFollowCrownExitNode()
				}
			}
		})
	})
}
