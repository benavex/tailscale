// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"tailscale.com/types/logger"
)

// AWG parameter bounds — mirror of headscale's
// types.AWGConfig.Validate() ranges. Enforced on the client so a
// compromised control server cannot push wire-format-breaking or
// fingerprintable values via the CapabilityAmneziaWG MapResponse
// entry even after it has won the noise session.
const (
	awgMaxJc      = 128
	awgMaxJSize   = 1280
	awgMaxPadding = 1280
)

// ValidateAWGParams returns a non-nil error if any field in p is out
// of the safe range. Zero-valued (unset) fields are ignored — the
// merge logic in MergeAWGParams will fill them from env defaults.
// Call this on params extracted from the CapabilityAmneziaWG netmap
// entry before handing them to ApplyAWG.
func ValidateAWGParams(p AWGParams) error {
	if p.Jc != 0 && (p.Jc < 1 || p.Jc > awgMaxJc) {
		return fmt.Errorf("jc=%d out of [1,%d]", p.Jc, awgMaxJc)
	}
	if p.Jmin != 0 && (p.Jmin < 1 || p.Jmin > awgMaxJSize) {
		return fmt.Errorf("jmin=%d out of [1,%d]", p.Jmin, awgMaxJSize)
	}
	if p.Jmax != 0 {
		if p.Jmax > awgMaxJSize {
			return fmt.Errorf("jmax=%d exceeds %d", p.Jmax, awgMaxJSize)
		}
		// Only compare to jmin if it's also set. A CapMap payload that
		// sets jmax alone is legal (env var supplies jmin at merge time).
		if p.Jmin != 0 && p.Jmax < p.Jmin {
			return fmt.Errorf("jmax=%d < jmin=%d", p.Jmax, p.Jmin)
		}
	}
	for _, pair := range [...]struct {
		name string
		val  int
	}{{"s1", p.S1}, {"s2", p.S2}, {"s3", p.S3}, {"s4", p.S4}} {
		if pair.val < 0 || pair.val > awgMaxPadding {
			return fmt.Errorf("%s=%d out of [0,%d]", pair.name, pair.val, awgMaxPadding)
		}
	}
	for _, pair := range [...]struct {
		name, val string
	}{{"h1", p.H1}, {"h2", p.H2}, {"h3", p.H3}, {"h4", p.H4}} {
		if pair.val == "" {
			continue
		}
		if err := validateAWGMagicHeader(pair.val); err != nil {
			return fmt.Errorf("%s: %w", pair.name, err)
		}
	}
	return nil
}

// validateAWGMagicHeader parses a magic-header spec exactly as
// amneziawg-go's newMagicHeader does: "N" or "N-M" where both are
// uint32 and M >= N.
func validateAWGMagicHeader(spec string) error {
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return errors.New("bad format (want N or N-M)")
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	if len(parts) == 1 {
		return nil
	}
	end, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("end: %w", err)
	}
	if end < start {
		return fmt.Errorf("end %d < start %d", end, start)
	}
	return nil
}

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
