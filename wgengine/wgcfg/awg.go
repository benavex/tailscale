// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"os"
	"strconv"
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
