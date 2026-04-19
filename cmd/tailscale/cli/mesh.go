// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/mesh/invite"
)

// meshCmd groups user-facing commands for the benavex fork's mesh-VPN
// features. Kept small: first-contact pin is the only subcommand for
// now; failover + crown election run silently inside tailscaled.
var meshCmd = &ffcli.Command{
	Name:       "mesh",
	ShortUsage: "tailscale mesh <subcommand>",
	ShortHelp:  "Manage trust in a headscale mesh with cluster identity pinning",
	LongHelp: strings.TrimSpace(`
Mesh-specific subcommands.

  join      One-shot first-run: decode a vpn:// invite, pin, and log in.
  pin       Lower-level: first-contact pin against a verifier only.
`),
	Exec: func(ctx context.Context, args []string) error {
		return errors.New("usage: tailscale mesh <subcommand>; see --help")
	},
	Subcommands: []*ffcli.Command{meshJoinCmd, meshPinCmd},
}

var meshJoinCmd = &ffcli.Command{
	Name:       "join",
	ShortUsage: "tailscale mesh join <invite>",
	ShortHelp:  "First-run join using a single vpn:// invite string",
	LongHelp: strings.TrimSpace(`
Decode a vpn:// invite minted by the operator (see "headscale mesh
user-invite" on the server side) and run the full first-contact
sequence in one shot:

  1. Pin the cluster identity (verifier cross-check).
  2. Set ControlURL + follow-crown exit-node policy.
  3. Start tailscaled with the embedded pre-auth key.

The invite string tolerates whitespace and line wrapping — paste it
verbatim even if your terminal broke it across lines.
`),
	Exec: runMeshJoin,
}

func runMeshJoin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tailscale mesh join <invite>")
	}
	// Join all args in case the shell split the invite on whitespace
	// (e.g. user pasted a multi-line blob without quotes).
	raw := strings.Join(args, " ")
	inv, err := invite.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse invite: %w", err)
	}

	if _, err := localClient.ClusterPin(ctx, inv.URL, inv.Verifier); err != nil {
		return fmt.Errorf("cluster pin failed: %w", err)
	}
	printf("pinned cluster (verifier %s)\n", inv.Verifier)

	prefs := ipn.NewPrefs()
	prefs.ControlURL = inv.URL
	prefs.WantRunning = true
	prefs.AutoExitNode = "follow-crown"
	if err := localClient.Start(ctx, ipn.Options{
		UpdatePrefs: prefs,
		AuthKey:     inv.AuthKey,
	}); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	outln("logged in; tailscaled will come up in a few seconds.")
	return nil
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
