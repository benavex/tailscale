// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"strings"
	"testing"
)

// TestValidateAWGParamsAccepts: the reference AmneziaVPN defaults
// (which this fork also uses) must pass.
func TestValidateAWGParamsAccepts(t *testing.T) {
	good := AWGParams{
		Jc:   3,
		Jmin: 10,
		Jmax: 30,
		S1:   15,
		S2:   18,
		S3:   20,
		S4:   23,
		H1:   "1020325451",
		H2:   "3288052141",
		H3:   "1766607858",
		H4:   "2528465083",
	}
	if err := ValidateAWGParams(good); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
}

// TestValidateAWGParamsZeroFieldsOK: unset (zero) fields are ignored
// so env-var merge can supply them.
func TestValidateAWGParamsZeroFieldsOK(t *testing.T) {
	if err := ValidateAWGParams(AWGParams{}); err != nil {
		t.Fatalf("zero-value params rejected: %v", err)
	}
}

// TestValidateAWGParamsRejects: every out-of-range scenario must fail
// with a field-specific error.
func TestValidateAWGParamsRejects(t *testing.T) {
	base := AWGParams{
		Jc:   3,
		Jmin: 10,
		Jmax: 30,
		S1:   15,
		S2:   18,
		S3:   20,
		S4:   23,
	}
	cases := []struct {
		name  string
		mod   func(*AWGParams)
		match string
	}{
		{"jc too high", func(p *AWGParams) { p.Jc = 10000 }, "jc"},
		{"jmin too high", func(p *AWGParams) { p.Jmin = 999999 }, "jmin"},
		{"jmax below jmin", func(p *AWGParams) { p.Jmin = 100; p.Jmax = 50 }, "jmax"},
		{"s1 too high", func(p *AWGParams) { p.S1 = 99999 }, "s1"},
		{"s2 negative", func(p *AWGParams) { p.S2 = -1 }, "s2"},
		{"h1 malformed", func(p *AWGParams) { p.H1 = "abc" }, "h1"},
		{"h1 reversed range", func(p *AWGParams) { p.H1 = "500-100" }, "h1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mod(&p)
			err := ValidateAWGParams(p)
			if err == nil || !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("want error mentioning %q, got %v", tc.match, err)
			}
		})
	}
}
