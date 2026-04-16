// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"tailscale.com/types/logger"
)

// AmneziaVPN client defaults, mirrored from
// amnezia-client/client/protocols/protocols_defs.h (namespace protocols::awg).
// Used when the matching TS_AWG_* env var is unset so two peers both built
// from this fork agree on a non-trivial obfuscation profile out of the box.
const (
	defaultJc   = 3
	defaultJmin = 10
	defaultJmax = 30
	defaultS1   = 15
	defaultS2   = 18
	defaultS3   = 20
	defaultS4   = 23
	defaultH1   = "1020325451" // init
	defaultH2   = "3288052141" // response
	defaultH3   = "1766607858" // underload
	defaultH4   = "2528465083" // transport
)

// AWGParamsFromEnv reads AmneziaWG obfuscation parameters from TS_AWG_*
// environment variables. Any unset var falls back to the AmneziaVPN client
// default for that field, so obfuscation is on by default when this binary
// is used.
//
// This is the provisional source of parameters for Phase 1 of the mesh-VPN
// project. Phase 2 will distribute them via Headscale/MapResponse.
//
// Recognised vars:
//
//	TS_AWG_JC, TS_AWG_JMIN, TS_AWG_JMAX     (positive ints, junk packets)
//	TS_AWG_S1..TS_AWG_S4                    (non-negative ints, padding)
//	TS_AWG_H1..TS_AWG_H4                    (strings, magic-header specs
//	                                         "N" or "N-M", see magic-header.go)
func AWGParamsFromEnv() AWGParams {
	return AWGParams{
		Jc:   envIntDefault("TS_AWG_JC", defaultJc),
		Jmin: envIntDefault("TS_AWG_JMIN", defaultJmin),
		Jmax: envIntDefault("TS_AWG_JMAX", defaultJmax),
		S1:   envIntDefault("TS_AWG_S1", defaultS1),
		S2:   envIntDefault("TS_AWG_S2", defaultS2),
		S3:   envIntDefault("TS_AWG_S3", defaultS3),
		S4:   envIntDefault("TS_AWG_S4", defaultS4),
		H1:   envStrDefault("TS_AWG_H1", defaultH1),
		H2:   envStrDefault("TS_AWG_H2", defaultH2),
		H3:   envStrDefault("TS_AWG_H3", defaultH3),
		H4:   envStrDefault("TS_AWG_H4", defaultH4),
	}
}

func envIntDefault(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envStrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// MergeAWGParams returns primary with any zero-valued field filled in
// from fallback. Used to combine headscale-published params (primary,
// source of truth) with the local env-var derived defaults (fallback)
// so operators can override individual keys per-node without having to
// republish a complete set from the server.
func MergeAWGParams(primary, fallback AWGParams) AWGParams {
	if primary.Jc == 0 {
		primary.Jc = fallback.Jc
	}
	if primary.Jmin == 0 {
		primary.Jmin = fallback.Jmin
	}
	if primary.Jmax == 0 {
		primary.Jmax = fallback.Jmax
	}
	if primary.S1 == 0 {
		primary.S1 = fallback.S1
	}
	if primary.S2 == 0 {
		primary.S2 = fallback.S2
	}
	if primary.S3 == 0 {
		primary.S3 = fallback.S3
	}
	if primary.S4 == 0 {
		primary.S4 = fallback.S4
	}
	if primary.H1 == "" {
		primary.H1 = fallback.H1
	}
	if primary.H2 == "" {
		primary.H2 = fallback.H2
	}
	if primary.H3 == "" {
		primary.H3 = fallback.H3
	}
	if primary.H4 == "" {
		primary.H4 = fallback.H4
	}
	return primary
}

// uapiString serialises p to the device-level UAPI lines understood by
// amneziawg-go. Fields with zero/empty values are omitted. Returns an empty
// string when nothing is set so callers can cheaply skip the IpcSet.
func (p AWGParams) uapiString() string {
	if p.IsZero() {
		return ""
	}
	var sb strings.Builder
	writeInt := func(k string, v int) {
		if v != 0 {
			fmt.Fprintf(&sb, "%s=%d\n", k, v)
		}
	}
	writeStr := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&sb, "%s=%s\n", k, v)
		}
	}
	writeInt("jc", p.Jc)
	writeInt("jmin", p.Jmin)
	writeInt("jmax", p.Jmax)
	writeInt("s1", p.S1)
	writeInt("s2", p.S2)
	writeInt("s3", p.S3)
	writeInt("s4", p.S4)
	writeStr("h1", p.H1)
	writeStr("h2", p.H2)
	writeStr("h3", p.H3)
	writeStr("h4", p.H4)
	return sb.String()
}

// ApplyAWG writes p to d via IpcSet as a device-only configuration (no peer
// section). Zero-valued params are omitted. It is a no-op if p is zero.
// Returns any error reported by the engine.
func ApplyAWG(d *device.Device, p AWGParams, logf logger.Logf) error {
	s := p.uapiString()
	if s == "" {
		return nil
	}
	if err := d.IpcSet(s); err != nil {
		return fmt.Errorf("wgcfg: apply AmneziaWG params: %w", err)
	}
	logf("wgcfg: applied AmneziaWG params: jc=%d jmin=%d jmax=%d s1=%d s2=%d s3=%d s4=%d h1=%q h2=%q h3=%q h4=%q",
		p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.S3, p.S4, p.H1, p.H2, p.H3, p.H4)
	return nil
}
