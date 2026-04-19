// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package invite bundles the first-run values — bootstrap URL,
// 8-char cluster verifier, and pre-auth key — into one opaque string
// the operator can hand to a user device. The client-side CLI and the
// Android app both decode it and run first-contact pin + login in one
// step instead of three separate copy-paste boxes.
//
// Wire format:
//
//	vpn://<base64url-nopad-of-json>
//
// The first byte of the decoded JSON payload carries a single-digit
// version under the "z" key so a breaking change doesn't require a
// new URL scheme. Current version is 1. Parse strips every ASCII
// whitespace rune before decoding, so a string copied out of a
// terminal that word-wrapped mid-blob still round-trips.

package invite

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Scheme is the URL-style prefix. Everything after is base64url.
const Scheme = "vpn://"

// Version is the current payload version written by Format.
const Version = 1

// Invite is the decoded payload. Single-letter JSON keys keep the
// encoded string as short as possible without inventing a
// custom binary format (~15 bytes of JSON overhead total).
type Invite struct {
	Ver      int    `json:"z"`           // payload format version, current = 1
	URL      string `json:"u"`           // bootstrap URL, e.g. https://hs42.duckdns.org
	Verifier string `json:"v"`           // 8-char cluster verifier (base32-no-pad)
	AuthKey  string `json:"k"`           // pre-auth key, e.g. hskey-auth-...
	Note     string `json:"n,omitempty"` // operator-supplied human label
}

// Format encodes inv as a paste-safe vpn:// string. No whitespace is
// emitted — callers that want to wrap for display should do it at
// render time; Parse restores the original regardless.
func Format(inv Invite) (string, error) {
	if inv.Ver == 0 {
		inv.Ver = Version
	}
	if err := validate(inv); err != nil {
		return "", err
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("marshal invite: %w", err)
	}
	return Scheme + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Parse accepts anything a user might plausibly paste — with stray
// spaces, tabs, newlines, carriage returns — and returns the decoded
// Invite. The "vpn://" scheme is required (case-insensitive) so a
// typo produces an explicit error rather than a cryptic base64 failure.
func Parse(s string) (Invite, error) {
	clean := stripWhitespace(s)
	if clean == "" {
		return Invite{}, errors.New("empty invite string")
	}
	if len(clean) < len(Scheme) || !strings.EqualFold(clean[:len(Scheme)], Scheme) {
		return Invite{}, fmt.Errorf("invite must start with %q (got %.10q…)", Scheme, clean)
	}
	payload := clean[len(Scheme):]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Invite{}, fmt.Errorf("decode base64 payload: %w", err)
	}
	var inv Invite
	if err := json.Unmarshal(raw, &inv); err != nil {
		return Invite{}, fmt.Errorf("decode invite json: %w", err)
	}
	if inv.Ver != Version {
		return Invite{}, fmt.Errorf("unsupported invite version z=%d (this client understands %d)", inv.Ver, Version)
	}
	if err := validate(inv); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func validate(inv Invite) error {
	if inv.URL == "" {
		return errors.New("invite missing url (u)")
	}
	if !strings.HasPrefix(inv.URL, "http://") && !strings.HasPrefix(inv.URL, "https://") {
		return fmt.Errorf("invite url must start with http:// or https:// (got %q)", inv.URL)
	}
	if len(inv.Verifier) != 8 {
		return fmt.Errorf("invite verifier must be 8 chars (got %d: %q)", len(inv.Verifier), inv.Verifier)
	}
	if inv.AuthKey == "" {
		return errors.New("invite missing auth key (k)")
	}
	return nil
}

// stripWhitespace removes every unicode whitespace rune. Tolerates
// terminal word-wrap, paste artifacts, trailing newlines.
func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
