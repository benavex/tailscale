// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nmcfg converts a controlclient.NetMap into a wgcfg config.
package nmcfg

import (
	"bufio"
	"cmp"
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
)

// CapabilityAmneziaWG is the node capability under which headscale
// publishes AmneziaWG obfuscation parameters in the requesting node's
// SelfNode.CapMap. Payload is a JSON object with fields matching
// [wgcfg.AWGParams]. Keep in sync with headscale's
// hscontrol/types.CapabilityAmneziaWG.
const CapabilityAmneziaWG tailcfg.NodeCapability = "benavex.com/cap/amneziawg"

// CapabilityMesh is the node capability under which headscale
// publishes the mesh view (self + peers + currently-elected crown)
// so clients can fail over to another control server without DNS.
// Payload is a JSON object; see [MeshSnapshot].
const CapabilityMesh tailcfg.NodeCapability = "benavex.com/cap/mesh"

// MeshPeer is one sibling control server as seen by the crown-election
// subsystem on the local headscale.
type MeshPeer struct {
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	Online        bool    `json:"online"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	Score         float64 `json:"score"`

	// NoisePubHex is this peer's noise protocol pubkey, hex-encoded.
	// Populated when the cluster uses identity pinning. Empty in
	// legacy single-server or secret-less deployments.
	NoisePubHex string `json:"noise_pub,omitempty"`

	// ClusterSigHex is ed25519.Sign(cluster_priv, NoisePubHex-bytes).
	// The client refuses to rotate ControlURL to this peer unless the
	// pair (NoisePubHex, ClusterSigHex) verifies under the pinned
	// cluster pubkey.
	ClusterSigHex string `json:"cluster_sig,omitempty"`

	// ExitNodeName is the tailnet hostname of the per-VPS tailscaled
	// that runs alongside this peer's headscale and advertises an
	// exit-node route. Used by follow-crown egress mode: when this
	// peer is the elected crown, the client looks up the netmap node
	// whose name matches this field and pins ExitNodeID to it.
	ExitNodeName string `json:"exit_node_name,omitempty"`
}

// MeshSnapshot is the payload of [CapabilityMesh]. Mirrors
// hscontrol/mesh.Snapshot on the server side.
type MeshSnapshot struct {
	Self  MeshPeer   `json:"self"`
	Peers []MeshPeer `json:"peers"`
	Crown string     `json:"crown"`
}

// ExtractMesh reads [CapabilityMesh] from the netmap SelfNode. Returns
// a zero-value MeshSnapshot and ok=false when the cap is missing or
// malformed; the caller may treat that as "no mesh / operator is on a
// single-server install".
func ExtractMesh(nm *netmap.NetworkMap) (MeshSnapshot, bool) {
	if nm == nil || !nm.SelfNode.Valid() {
		return MeshSnapshot{}, false
	}
	vals, err := tailcfg.UnmarshalNodeCapViewJSON[MeshSnapshot](nm.SelfNode.CapMap(), CapabilityMesh)
	if err != nil || len(vals) == 0 {
		return MeshSnapshot{}, false
	}
	return vals[0], true
}

func nodeDebugName(n tailcfg.NodeView) string {
	name, _, _ := strings.Cut(cmp.Or(n.Name(), n.Hostinfo().Hostname()), ".")
	return name
}

// cidrIsSubnet reports whether cidr is a non-default-route subnet
// exported by node that is not one of its own self addresses.
func cidrIsSubnet(node tailcfg.NodeView, cidr netip.Prefix) bool {
	if cidr.Bits() == 0 {
		return false
	}
	if !cidr.IsSingleIP() {
		return true
	}
	if tsaddr.IsTailscaleIP(cidr.Addr()) {
		return false
	}
	for _, selfCIDR := range node.Addresses().All() {
		if cidr == selfCIDR {
			return false
		}
	}
	return true
}

// WGCfg returns the NetworkMaps's WireGuard configuration.
func WGCfg(pk key.NodePrivate, nm *netmap.NetworkMap, logf logger.Logf, flags netmap.WGConfigFlags, exitNode tailcfg.StableNodeID) (*wgcfg.Config, error) {
	cfg := &wgcfg.Config{
		PrivateKey: pk,
		Addresses:  nm.GetAddresses().AsSlice(),
		Peers:      make([]wgcfg.Peer, 0, len(nm.Peers)),
	}

	// Setup log IDs for data plane audit logging.
	if nm.SelfNode.Valid() {
		canNetworkLog := nm.SelfNode.HasCap(tailcfg.CapabilityDataPlaneAuditLogs)
		logExitFlowEnabled := nm.SelfNode.HasCap(tailcfg.NodeAttrLogExitFlows)
		if canNetworkLog && nm.SelfNode.DataPlaneAuditLogID() != "" && nm.DomainAuditLogID != "" {
			nodeID, errNode := logid.ParsePrivateID(nm.SelfNode.DataPlaneAuditLogID())
			if errNode != nil {
				logf("[v1] wgcfg: unable to parse node audit log ID: %v", errNode)
			}
			domainID, errDomain := logid.ParsePrivateID(nm.DomainAuditLogID)
			if errDomain != nil {
				logf("[v1] wgcfg: unable to parse domain audit log ID: %v", errDomain)
			}
			if errNode == nil && errDomain == nil {
				cfg.NetworkLogging.NodeID = nodeID
				cfg.NetworkLogging.DomainID = domainID
				cfg.NetworkLogging.LogExitFlowEnabled = logExitFlowEnabled
			}
		}

		// Pull AmneziaWG obfuscation params published by headscale via
		// CapabilityAmneziaWG. When both netmap and env vars supply
		// values, netmap wins (server is the source of truth); zero-valued
		// fields in the cap fall back to the env var equivalent so the
		// operator can override individual keys locally.
		//
		// Range-check every field before accepting. A compromised control
		// server that has won the noise session could otherwise push
		// fingerprintable or pathological values (Jc=10000, S1=1MB) here;
		// rejecting the whole cap is safer than partial application.
		if vals, err := tailcfg.UnmarshalNodeCapViewJSON[wgcfg.AWGParams](nm.SelfNode.CapMap(), CapabilityAmneziaWG); err != nil {
			logf("[v1] wgcfg: ignoring malformed %s cap: %v", CapabilityAmneziaWG, err)
		} else if len(vals) > 0 {
			if err := wgcfg.ValidateAWGParams(vals[0]); err != nil {
				logf("[v1] wgcfg: rejecting out-of-range %s cap: %v", CapabilityAmneziaWG, err)
			} else {
				cfg.AWG = wgcfg.MergeAWGParams(vals[0], wgcfg.AWGParamsFromEnv())
			}
		}

		// Log the mesh view whenever a netmap arrives carrying it. The
		// actual control-URL rotation is done elsewhere (see
		// [ipnlocal.LocalBackend.meshFailover]); here we just surface it
		// to operators running `tail -f tailscaled.log` who want a quick
		// read on which control server is currently the crown.
		if snap, ok := ExtractMesh(nm); ok {
			peerNames := make([]string, 0, len(snap.Peers))
			for _, p := range snap.Peers {
				state := "offline"
				if p.Online {
					state = "online"
				}
				peerNames = append(peerNames, p.Name+"("+state+")")
			}
			logf("mesh: self=%s crown=%s peers=%v",
				snap.Self.Name, snap.Crown, peerNames)
		}
	}

	var skippedExitNode, skippedSubnetRouter, skippedExpired []tailcfg.NodeView

	for _, peer := range nm.Peers {
		if peer.DiscoKey().IsZero() && peer.HomeDERP() == 0 && !peer.IsWireGuardOnly() {
			// Peer predates both DERP and active discovery, we cannot
			// communicate with it.
			logf("[v1] wgcfg: skipped peer %s, doesn't offer DERP or disco", peer.Key().ShortString())
			continue
		}
		// Skip expired peers; we'll end up failing to connect to them
		// anyway, since control intentionally breaks node keys for
		// expired peers so that we can't discover endpoints via DERP.
		if peer.Expired() {
			skippedExpired = append(skippedExpired, peer)
			continue
		}

		cfg.Peers = append(cfg.Peers, wgcfg.Peer{
			PublicKey: peer.Key(),
			DiscoKey:  peer.DiscoKey(),
		})
		cpeer := &cfg.Peers[len(cfg.Peers)-1]

		didExitNodeLog := false
		cpeer.V4MasqAddr = peer.SelfNodeV4MasqAddrForThisPeer().Clone()
		cpeer.V6MasqAddr = peer.SelfNodeV6MasqAddrForThisPeer().Clone()
		cpeer.IsJailed = peer.IsJailed()
		for _, allowedIP := range peer.AllowedIPs().All() {
			if allowedIP.Bits() == 0 && peer.StableID() != exitNode {
				if didExitNodeLog {
					// Don't log about both the IPv4 /0 and IPv6 /0.
					continue
				}
				didExitNodeLog = true
				skippedExitNode = append(skippedExitNode, peer)
				continue
			} else if cidrIsSubnet(peer, allowedIP) {
				if (flags & netmap.AllowSubnetRoutes) == 0 {
					skippedSubnetRouter = append(skippedSubnetRouter, peer)
					continue
				}
			}
			cpeer.AllowedIPs = append(cpeer.AllowedIPs, allowedIP)
		}
	}

	logList := func(title string, nodes []tailcfg.NodeView) {
		if len(nodes) == 0 {
			return
		}
		logf("[v1] wgcfg: %s from %d nodes: %s", title, len(nodes), logger.ArgWriter(func(bw *bufio.Writer) {
			const max = 5
			for i, n := range nodes {
				if i == max {
					fmt.Fprintf(bw, "... +%d", len(nodes)-max)
					return
				}
				if i > 0 {
					bw.WriteString(", ")
				}
				fmt.Fprintf(bw, "%s (%s)", nodeDebugName(n), n.StableID())
			}
		}))
	}
	logList("skipped unselected exit nodes", skippedExitNode)
	logList("did not accept subnet routes", skippedSubnetRouter)
	logList("skipped expired peers", skippedExpired)

	return cfg, nil
}
