// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

// meshCmd groups user-facing commands for the benavex fork's mesh-VPN
// features. Kept small: first-contact pin is the only subcommand for
// now; failover + crown election run silently inside tailscaled.
var meshCmd = &ffcli.Command{
	Name:       "mesh",
	ShortUsage: "tailscale mesh <subcommand>",
	ShortHelp:  "Manage trust in a headscale mesh with cluster identity pinning",
	LongHelp: strings.TrimSpace(`
Mesh-specific subcommands. Currently:

  pin       First-contact pin a headscale mesh against an 8-character verifier.
`),
	Exec: func(ctx context.Context, args []string) error {
		return errors.New("usage: tailscale mesh <subcommand>; see --help")
	},
	Subcommands: []*ffcli.Command{meshPinCmd},
}

var meshPinCmd = &ffcli.Command{
	Name:       "pin",
	ShortUsage: "tailscale mesh pin <bootstrap-url> <verifier>",
	ShortHelp:  "One-time cluster-identity pin against an 8-character verifier",
	LongHelp: strings.TrimSpace(`
Run once per device to pin this tailscaled to a headscale mesh. Supply:

  bootstrap-url   Any reachable headscale URL (e.g. https://hs42.duckdns.org).
  verifier        The 8-character string printed by the operator on startup.

The daemon fetches the cluster identity over HTTPS, refuses to pin if the
returned cluster key does not hash to your verifier (defeats DNS poisoning),
and persists the cluster public key in varRoot/clusterpin.json.

After the pin is installed, sibling control servers advertised via the mesh
snapshot must carry a cluster-signed noise pubkey or tailscaled will refuse
to fail over to them.

Idempotent: re-pinning the same cluster key is a no-op; re-pinning a
different key fails with "pin mismatch" — delete varRoot/clusterpin.json
out-of-band to force a re-pin (factory-reset semantics).
`),
	Exec: runMeshPin,
}

func runMeshPin(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tailscale mesh pin <bootstrap-url> <verifier>")
	}
	bootstrap := strings.TrimSpace(args[0])
	verifier := strings.ToUpper(strings.TrimSpace(args[1]))
	if bootstrap == "" {
		return errors.New("bootstrap-url is required")
	}
	if len(verifier) != 8 {
		return fmt.Errorf("verifier must be exactly 8 characters, got %d (%q)", len(verifier), verifier)
	}

	res, err := localClient.ClusterPin(ctx, bootstrap, verifier)
	if err != nil {
		return fmt.Errorf("cluster pin failed: %w", err)
	}
	printf("pinned cluster %s (verifier %s)\n", res.ClusterPub, res.Verifier)
	outln("you can now run `tailscale up --login-server=" + bootstrap + "` safely.")
	return nil
}
