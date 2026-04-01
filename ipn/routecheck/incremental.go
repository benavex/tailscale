// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"net/netip"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
	"tailscale.com/wgengine"
)

// Init loads the initial [netmap.NetworkMap] assuming that a peer is reachable
// if it’s connected to the control plane, i.e. [tailcfg.Hostinfo.Online] is set.
// That’s not necessarily true, but we must make early routing decisions
// before active probing is complete.
func (c *Client) init(nm *netmap.NetworkMap) {
	var r = &Report{
		reachable: make(set.Set[tailcfg.NodeID]),
	}

	nids := make(map[key.NodePublic]tailcfg.NodeID)
	for _, n := range nm.Peers {
		if !n.Valid() {
			continue
		}
		if len(routes(n)) == 0 {
			// Connectors, i.e. exit nodes or subnet routers,
			// are the only nodes that are chosen by reachability.
			// Peer with no routes don’t need to be checked.
			continue
		}
		if n.Online().Get() {
			r.reachable.Add(n.ID())
			nids[n.Key()] = n.ID()
		}
	}
	r.Now = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.report = r
	c.nids = nids
}

// Watch compares the previous set of traffic flows to the current ones.
// If we are receiving data from a peer, then we know that it is reachable.
// Otherwise, we will need to actively probe that peer to be sure.
func (c *Client) watch(flows map[key.NodePublic]ipnstate.PeerStatusLite) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: consult the netmap to remove nodes that are gone and add new nodes.

	prev := c.flows
	for k, s := range c.flows {
		if prev[k].RxBytes != s.RxBytes { // wraparound is possible
			nid := c.nids[k]
			c.report.reachable.Add(nid)
		}
	}
	c.report.Now = time.Now()
	c.flows = flows

	// TODO: What do I do with good after this? Is this where we set the tripwire?
}

// Report generates and returns a reachability report by either
// passively checking for activity in each node’s [ipnstate.PeerStatusLite] or
// by actively probing.
func (c *Client) Report(ctx context.Context) (*Report, error) {
	status := c.b.Status().Peer
	r := Report{reachable: make(set.Set[tailcfg.NodeID])}
	for pfx, peers := range c.RoutersByPrefix() {
		for _, n := range peers {
			nid := n.ID()
			if _, ok := r.reachable[nid]; ok {
				continue // Already probed
			}

			if st := status[n.Key()]; st != nil {
				rx, tx := st.RxBytes, st.TxBytes
				last := st.LastHandshake
				// Check if the previous status is any good
			}
		}
	}
	r.Now = time.Now()
	return &r, nil
}

// GetReport gets a report by probing all .
func (c *Client) UpdateReport(ctx context.Context, r *Report, routes []netip.Prefix) (*Report, error) {
	return &Report{
		Now: time.Now(),
	}, nil
}

// TODO: The GUIs use something like NotifyWatchEngineUpdates on the ipnbus. We should do something similar, since that will update things every 2 seconds via c.b.pollRequestEngineStatus.
// We should also check ipn.NotifyInitialNetMap to just set Online for everything.
// StatusCallback
func (c *Client) setWgengineStatus(s *wgengine.Status, err error) {
	if err != nil {
		c.logf("wgengine status error: %v", err)
		return
	}
	if s == nil {
		c.logf("[unexpected] non-error wgengine update with status=nil: %v", s)
		return
	}
	p := s.Peers

}
