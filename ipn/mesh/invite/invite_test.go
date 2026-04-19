// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package invite

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Invite{
		URL:      "https://hs42.duckdns.org",
		Verifier: "ABCD1234",
		AuthKey:  "hskey-auth-abcdefghijklmnopqrstuvwxyz1234567890",
		Note:     "phone-alice",
	}
	s, err := Format(in)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.HasPrefix(s, Scheme) {
		t.Fatalf("missing %q scheme: %s", Scheme, s)
	}
	got, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Ver != Version {
		t.Errorf("Ver = %d, want %d", got.Ver, Version)
	}
	if got.URL != in.URL || got.Verifier != in.Verifier || got.AuthKey != in.AuthKey || got.Note != in.Note {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, in)
	}
}

// The real point of Format/Parse: strings that got wrapped, truncated
// with CRs, pasted through a terminal, etc. must still decode.
func TestParseTolerantWhitespace(t *testing.T) {
	base, err := Format(Invite{
		URL:      "https://hs42.duckdns.org",
		Verifier: "XYZ45678",
		AuthKey:  "hskey-auth-short",
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	mangled := strings.Builder{}
	mangled.WriteString("  \t")
	for i, r := range base {
		if i > 0 && i%6 == 0 {
			mangled.WriteString(" \n")
		}
		if i > 0 && i%11 == 0 {
			mangled.WriteString("\r\n\t")
		}
		mangled.WriteRune(r)
	}
	mangled.WriteString("\n\n")

	got, err := Parse(mangled.String())
	if err != nil {
		t.Fatalf("Parse mangled: %v", err)
	}
	if got.Verifier != "XYZ45678" {
		t.Errorf("Verifier = %q, want XYZ45678", got.Verifier)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	enc := func(j string) string {
		return Scheme + base64.RawURLEncoding.EncodeToString([]byte(j))
	}
	cases := map[string]string{
		"empty":          "",
		"whitespace":     "   \n\t   ",
		"wrong scheme":   "mesh1:eyJ6IjoxfQ",
		"no scheme":      "eyJ6IjoxfQ",
		"bad base64":     "vpn://!!!not-base64!!!",
		"bad json":       Scheme + base64.RawURLEncoding.EncodeToString([]byte("not json")),
		"wrong version":  enc(`{"z":99,"u":"https://x","v":"ABCD1234","k":"k"}`),
		"bad url scheme": enc(`{"z":1,"u":"ftp://x","v":"ABCD1234","k":"k"}`),
		"short verifier": enc(`{"z":1,"u":"https://x","v":"A","k":"k"}`),
		"missing key":    enc(`{"z":1,"u":"https://x","v":"ABCD1234"}`),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(s); err == nil {
				t.Errorf("Parse(%q) = nil, want error", s)
			}
		})
	}
}
