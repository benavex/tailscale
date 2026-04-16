// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"net/netip"
	"slices"

	"tailscale.com/types/key"
	"tailscale.com/types/logid"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config,Peer

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
type Config struct {
	PrivateKey key.NodePrivate
	Addresses  []netip.Prefix
	MTU        uint16
	DNS        []netip.Addr
	Peers      []Peer

	// NetworkLogging enables network logging.
	// It is disabled if either ID is the zero value.
	// LogExitFlowEnabled indicates whether or not exit flows should be logged.
	NetworkLogging struct {
		NodeID             logid.PrivateID
		DomainID           logid.PrivateID
		LogExitFlowEnabled bool
	}

	// AWG holds AmneziaWG obfuscation parameters applied at the device level.
	// Zero values are not emitted to the underlying engine.
	AWG AWGParams
}

// AWGParams holds the device-level AmneziaWG obfuscation parameters.
// Zero values mean "not set" and are omitted from the UAPI stream.
// The underlying amneziawg-go engine rejects re-setting a previously-set
// value to <= 0, so these should be configured once at startup.
type AWGParams struct {
	Jc   int // junk packet count
	Jmin int // junk packet min size
	Jmax int // junk packet max size
	S1   int // padding size added to handshake init
	S2   int // padding size added to handshake response
	S3   int // padding size added to cookie reply
	S4   int // padding size added to transport data
	H1   string // magic-header spec for handshake init ("N" or "N-M")
	H2   string // magic-header spec for handshake response
	H3   string // magic-header spec for cookie reply
	H4   string // magic-header spec for transport data
}

// IsZero reports whether p has no fields set.
func (p AWGParams) IsZero() bool { return p == (AWGParams{}) }

func (c *Config) Equal(o *Config) bool {
	if c == nil || o == nil {
		return c == o
	}
	return c.PrivateKey.Equal(o.PrivateKey) &&
		c.MTU == o.MTU &&
		c.NetworkLogging == o.NetworkLogging &&
		c.AWG == o.AWG &&
		slices.Equal(c.Addresses, o.Addresses) &&
		slices.Equal(c.DNS, o.DNS) &&
		slices.EqualFunc(c.Peers, o.Peers, Peer.Equal)
}

type Peer struct {
	PublicKey           key.NodePublic
	DiscoKey            key.DiscoPublic // present only so we can handle restarts within wgengine, not passed to WireGuard
	AllowedIPs          []netip.Prefix
	V4MasqAddr          *netip.Addr // if non-nil, masquerade IPv4 traffic to this peer using this address
	V6MasqAddr          *netip.Addr // if non-nil, masquerade IPv6 traffic to this peer using this address
	IsJailed            bool        // if true, this peer is jailed and cannot initiate connections
	PersistentKeepalive uint16      // in seconds between keep-alives; 0 to disable
	// wireguard-go's endpoint for this peer. It should always equal Peer.PublicKey.
	// We represent it explicitly so that we can detect if they diverge and recover.
	// There is no need to set WGEndpoint explicitly when constructing a Peer by hand.
	// It is only populated when reading Peers from wireguard-go.
	WGEndpoint key.NodePublic
}

func addrPtrEq(a, b *netip.Addr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func (p Peer) Equal(o Peer) bool {
	return p.PublicKey == o.PublicKey &&
		p.DiscoKey == o.DiscoKey &&
		slices.Equal(p.AllowedIPs, o.AllowedIPs) &&
		p.IsJailed == o.IsJailed &&
		p.PersistentKeepalive == o.PersistentKeepalive &&
		addrPtrEq(p.V4MasqAddr, o.V4MasqAddr) &&
		addrPtrEq(p.V6MasqAddr, o.V6MasqAddr) &&
		p.WGEndpoint == o.WGEndpoint
}

// PeerWithKey returns the Peer with key k and reports whether it was found.
func (config Config) PeerWithKey(k key.NodePublic) (Peer, bool) {
	for _, p := range config.Peers {
		if p.PublicKey == k {
			return p, true
		}
	}
	return Peer{}, false
}
