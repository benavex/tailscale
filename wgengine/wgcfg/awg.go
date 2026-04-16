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

// AWGParamsFromEnv reads AmneziaWG obfuscation parameters from TS_AWG_*
// environment variables. Unset or unparseable values are left at zero.
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
		Jc:   envInt("TS_AWG_JC"),
		Jmin: envInt("TS_AWG_JMIN"),
		Jmax: envInt("TS_AWG_JMAX"),
		S1:   envInt("TS_AWG_S1"),
		S2:   envInt("TS_AWG_S2"),
		S3:   envInt("TS_AWG_S3"),
		S4:   envInt("TS_AWG_S4"),
		H1:   os.Getenv("TS_AWG_H1"),
		H2:   os.Getenv("TS_AWG_H2"),
		H3:   os.Getenv("TS_AWG_H3"),
		H4:   os.Getenv("TS_AWG_H4"),
	}
}

func envInt(k string) int {
	v := os.Getenv(k)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
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
