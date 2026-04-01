// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck performs status checks for routes from the current host.
package routecheck

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
)

// Nodeset is a set of nodes keyed by node ID, so duplicates are easily detected.
// To prevent stuttering, it encodes itself as an array.
type nodeset map[tailcfg.NodeID]Node

var _ json.Marshaler = nodeset{}
var _ json.Unmarshaler = nodeset{}

// MarshalJSON implements the [json.Marshaler] interface.
func (ns nodeset) MarshalJSON() ([]byte, error) {
	nodes := maps.Values(ns)
	return json.Marshal(slices.Collect(nodes))
}

// MarshalJSON implements the [json.Unmarshaler] interface.
func (ns nodeset) UnmarshalJSON(b []byte) error {
	var nodes []Node
	if err := json.Unmarshal(b, &nodes); err != nil {
		return err
	}
	for _, n := range nodes {
		ns[n.ID] = n
	}
	return nil
}

// Node represents a node in the reachability report.
type Node struct {
	ID tailcfg.NodeID `json:"id"`

	// Name is the FQDN of the node.
	// It is also the MagicDNS name for the node.
	// It has a trailing dot.
	// e.g. "host.tail-scale.ts.net."
	Name string `json:"name"`

	// Addr is the IP address that was probed.
	Addr netip.Addr `json:"addr"`
}

// Report contains the result of a single routecheck.
type Report struct {
	// Done is the time when the report was finished.
	Done time.Time `json:"done"`

	// Reachable is the set of nodes that were reachable from the current host
	// when this report was compiled. Missing nodes may or may not be reachable.
	Reachable nodeset `json:"reachable"`
}

// Client generates Reports describing the result of both passive and active
// reachability probing.
type Client struct {
	// Verbose enables verbose logging.
	Verbose bool

	// Logf optionally specifies where to log to.
	// If nil, log.Printf is used.
	Logf logger.Logf

	// These elements are read-only after initialization.
	b LocalBackend
}

// LocalBackend is implemented by [ipnlocal.LocalBackend].
type LocalBackend interface {
	NetMap() *netmap.NetworkMap
	Peers() []tailcfg.NodeView
	Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, size int) (*ipnstate.PingResult, error)
	WatchNotifications(ctx context.Context, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool))
	WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
}

// NewClient returns a client that probes its peers using this LocalBackend.
func NewClient(b LocalBackend) (*Client, error) {
	if b == nil {
		return nil, errors.New("LocalBackend must be set")
	}
	return &Client{b: b}, nil
}

// Report returns the latest reachability report.
// Returns nil if a report isn’t available, which happens during initialization.
func (c *Client) Report() *Report {
	// TODO(sfllaw): Return the latest snapshot produced by background probing.
	r, err := c.Refresh(context.TODO())
	if err != nil {
		c.logf("reachability report error: %v", err)
	}
	return r
}

// Refresh generates a new reachability report and returns it.
func (c *Client) Refresh(ctx context.Context) (*Report, error) {
	return c.ProbeAllHARouters(ctx, 5)
}

type probed struct {
	id   tailcfg.NodeID
	name string
	addr netip.Addr
}

func (c *Client) probe(ctx context.Context, nodes iter.Seq[probed], limit int) (*Report, error) {
	g, ctx := errgroup.WithContext(ctx)
	if limit > 0 {
		g.SetLimit(limit)
	}

	var mu syncs.Mutex
	r := &Report{}
	for n := range nodes {
		g.Go(func() error {
			pong, err := c.b.Ping(ctx, n.addr, tailcfg.PingTSMP, 0)
			if err != nil {
				// Returning an error would cancel the errgroup.
				c.vlogf("ping %s (%s): error: %v", n.addr, n.id, err)
			} else {
				c.vlogf("ping %s (%s): result: %f ms (err: %v)", n.addr, n.id, pong.LatencySeconds*1000, pong.Err)
			}

			mu.Lock()
			defer mu.Unlock()
			if _, ok := r.Reachable[n.id]; !ok {
				mak.Set(&r.Reachable, n.id, Node{
					ID:   n.id,
					Name: n.name,
					Addr: n.addr,
				})
			}
			return nil
		})
	}
	g.Wait()
	r.Done = time.Now()
	return r, nil
}

// Probe actively probes the sequence of nodes and returns a reachability [Report].
// If limit is positive, it limits the number of concurrent active probes;
// a limit of zero will ping every node at once.
// This function tries both the IPv4 and IPv6 addresses
func (c *Client) Probe(ctx context.Context, nodes iter.Seq[tailcfg.NodeView], limit int) (*Report, error) {
	var canIPv4, canIPv6 bool
	for _, ip := range c.b.NetMap().SelfNode.Addresses().All() {
		addr := ip.Addr()
		if addr.Is4() {
			canIPv4 = true
		} else if addr.Is6() {
			canIPv6 = true
		}
	}

	var dsts iter.Seq[probed] = func(yield func(probed) bool) {
		for n := range nodes {
			// Ping one of the tailnet addresses.
			for _, ip := range n.Addresses().All() {
				// Skip this probe if there is an IP version mismatch.
				addr := ip.Addr()
				if addr.Is4() && !canIPv4 {
					continue
				}
				if addr.Is6() && !canIPv6 {
					continue
				}

				if !yield(probed{
					id:   n.ID(),
					name: n.Name(),
					addr: addr,
				}) {
					return
				}
				break // We only need one address for every node.
			}
		}
	}
	return c.probe(ctx, dsts, limit)
}

// ProbeAllPeers actively probes all peers in parallel and returns a [Report]
// that identifies which nodes are reachable. If limit is positive, it limits
// the number of concurrent active probes; a limit of zero will ping every
// candidate at once.
func (c *Client) ProbeAllPeers(ctx context.Context, limit int) (*Report, error) {
	nm := c.waitForInitialNetMap(ctx)
	return c.Probe(ctx, slices.Values(nm.Peers), limit)
}

// ProbeAllHARouters actively probes all High Availability routers in parallel
// and returns a [Report] that identifies which of these routers are reachable.
// If limit is positive, it limits the number of concurrent active probes;
// a limit of zero will ping every candidate at once.
func (c *Client) ProbeAllHARouters(ctx context.Context, limit int) (*Report, error) {
	nm := c.waitForInitialNetMap(ctx)

	// When a prefix is routed by multiple nodes, we probe those nodes.
	// There is no point to probing a router when it is the only choice.
	// These nodes are referred to a High Availability (HA) routers.
	var nodes []tailcfg.NodeView
	for _, rs := range c.RoutersByPrefix() {
		if len(rs) <= 1 {
			continue
		}
		nodes = append(nodes, rs...) // Note: this introduces duplicates.
	}

	// Sort by Node.ID and deduplicate to avoid double-probing.
	slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	slices.CompactFunc(nodes, func(a, b tailcfg.NodeView) bool {
		return a.ID() == b.ID()
	})

	// To prevent swarming, each node should probe in a different order.
	seed := uint64(nm.SelfNode.ID())
	rnd := rand.New(rand.NewPCG(seed, seed))
	rnd.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	return c.Probe(ctx, slices.Values(nodes), limit)
}

// WaitForInitialNetMap returns the current [netmap.NetworkMap], if present.
// If the network map is missing because the client just started,
// this function will wait for the control plane to send it before returning.
func (c *Client) waitForInitialNetMap(ctx context.Context) *netmap.NetworkMap {
	nm := c.b.NetMap()
	if nm != nil {
		return nm
	}

	// Wait for the initial NetworkMap to arrive:
	c.b.WatchNotifications(ctx, ipn.NotifyInitialNetMap, nil, func(n *ipn.Notify) (keepGoing bool) {
		nm = n.NetMap
		return nm == nil // Keep going until nm contains a network map.
	})
	return nm
}

// Routers returns a sequence of nodes that are routers, which will advertise
// more [tailcfg.Node.AllowedIPs] than the node’s own [tailcfg.Node.Addresses].
func (c *Client) Routers() iter.Seq[tailcfg.NodeView] {
	return func(yield func(tailcfg.NodeView) bool) {
		for _, n := range c.b.Peers() {
		AllowedIPs:
			for _, pfx := range n.AllowedIPs().All() {
				// Routers never forward their own local addresses.
				for _, addr := range n.Addresses().All() {
					if pfx == addr {
						continue AllowedIPs
					}
				}
				if !yield(n) {
					return
				}
			}
		}
	}
}

// RoutersByPrefix returns a map of nodes that route for a particular subnet.
// Nodes that route for /0 prefixes are exit nodes, their subnet is the Internet.
func (c *Client) RoutersByPrefix() map[netip.Prefix][]tailcfg.NodeView {
	var routers map[netip.Prefix][]tailcfg.NodeView
	for _, n := range c.b.Peers() {
		for _, pfx := range n.AllowedIPs().All() {
			mak.Set(&routers, pfx, append(routers[pfx], n))
		}
		continue
	}
	return routers
}

// Routes returns a slice of subnets that the given node will route.
// If the node is an exit node, the result will contain at least one /0 prefix.
// If the node is a subnet router, the result will contain a smaller prefix.
// The result omits any prefix that is one of the node’s local addresses.
func routes(n tailcfg.NodeView) []netip.Prefix {
	var routes []netip.Prefix
AllowedIPs:
	for _, pfx := range n.AllowedIPs().All() {
		// Routers never forward their own local addresses.
		for _, addr := range n.Addresses().All() {
			if pfx == addr {
				continue AllowedIPs
			}
		}
		routes = append(routes, pfx)
	}
	return routes
}
