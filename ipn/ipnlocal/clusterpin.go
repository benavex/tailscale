// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Cluster identity pinning on the client. Stores the ed25519 public
// key of the headscale cluster once, on first contact, and verifies
// every subsequent control server a client rotates to carries a valid
// cluster signature over its noise pubkey.
//
// This defeats DNS poisoning of the bootstrap hostname and a
// compromised non-crown sibling impersonating the crown: without the
// cluster private half, no attacker can produce a valid signature. The
// pin is keyed to this binary's var root (e.g. /var/lib/tailscale) so
// a per-device factory reset re-enters the first-contact flow.
//
// See docs/mesh/identity.md on the server side for the paired
// /mesh/identity endpoint and derivation details.

package ipnlocal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"tailscale.com/net/tlsdial"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

// clusterPinFile is the on-disk name of the pin. Lives directly under
// varRoot so it's one file per machine, not per-profile — rotating
// user accounts must not drop the trust anchor.
const clusterPinFile = "clusterpin.json"

// clusterPin is the on-disk record.
//
//   - ClusterPubHex pins the cluster ed25519 signing key; every sibling
//     control server's noise pubkey must carry a valid cluster signature.
//   - TLSSPKIHex pins the SHA-256 of the cluster TLS cert's
//     SubjectPublicKeyInfo (empty on pins written before Phase B —
//     treated as "cert trust only via system store" for back-compat,
//     but the intended path is to re-pin via the first-contact flow to
//     capture it).
//   - Verifier is stored purely for diagnostics; authoritative check is
//     always re-derived from ClusterPubHex.
type clusterPin struct {
	ClusterPubHex string `json:"cluster_pub"`
	Verifier      string `json:"verifier"`
	TLSSPKIHex    string `json:"tls_spki,omitempty"`
}

// clusterPinPath returns the absolute path where the pin is stored for
// this backend, or "" when no var root is configured (e.g. in tests
// without SetVarRoot). Callers should skip verification when "".
func (b *LocalBackend) clusterPinPath() string {
	root := b.TailscaleVarRoot()
	if root == "" {
		return ""
	}
	return filepath.Join(root, clusterPinFile)
}

// loadClusterPin reads the pin from disk. Returns (nil, nil) when no
// pin exists yet — the caller should treat that as "first contact
// required" and refuse to rotate.
func (b *LocalBackend) loadClusterPin() (*clusterPin, error) {
	path := b.clusterPinPath()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cluster pin: %w", err)
	}
	var pin clusterPin
	if err := json.Unmarshal(raw, &pin); err != nil {
		return nil, fmt.Errorf("parse cluster pin: %w", err)
	}
	if pin.ClusterPubHex == "" {
		return nil, errors.New("cluster pin file present but empty")
	}
	return &pin, nil
}

// WriteClusterPin records the cluster pubkey + verifier + TLS SPKI.
// Idempotent: overwriting with the same pub+SPKI is a no-op; a different
// pub returns an error ("pin mismatch") so an operator sees an explicit
// rejection rather than silent re-pinning. To force a change, the user
// deletes the file out of band (factory-reset escape hatch). Callers
// may pass tlsSPKIHex == "" to write a legacy pin (back-compat with
// pre-Phase-B servers that did not publish tls_spki); on re-contact
// with a newer server that does publish it, the pin is promoted in
// place via a same-pubkey write so the SPKI gets captured.
func (b *LocalBackend) WriteClusterPin(clusterPubHex, verifier, tlsSPKIHex string) error {
	path := b.clusterPinPath()
	if path == "" {
		return errors.New("no var root configured; cannot persist cluster pin")
	}
	if got, _ := hex.DecodeString(clusterPubHex); len(got) != ed25519.PublicKeySize {
		return fmt.Errorf("cluster pubkey hex decodes to %d bytes, want %d",
			len(got), ed25519.PublicKeySize)
	}
	if tlsSPKIHex != "" {
		if got, _ := hex.DecodeString(tlsSPKIHex); len(got) != sha256.Size {
			return fmt.Errorf("tls_spki hex decodes to %d bytes, want %d",
				len(got), sha256.Size)
		}
	}
	existing, err := b.loadClusterPin()
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.ClusterPubHex != clusterPubHex {
			return fmt.Errorf("cluster pin mismatch: pinned=%s attempted=%s (factory-reset to change)",
				existing.Verifier, verifier)
		}
		// Same pub. Promote to include TLS SPKI if a fresher server
		// supplied one and the old pin was silent on it — the whole
		// point of re-pinning here is to catch Phase-B capable
		// clusters without forcing a factory-reset.
		if existing.TLSSPKIHex == tlsSPKIHex {
			return nil
		}
		if existing.TLSSPKIHex != "" && tlsSPKIHex != "" &&
			existing.TLSSPKIHex != tlsSPKIHex {
			return fmt.Errorf("cluster TLS SPKI mismatch: pinned=%s attempted=%s (factory-reset to change)",
				existing.TLSSPKIHex, tlsSPKIHex)
		}
	}
	tmp := path + ".tmp"
	raw, err := json.MarshalIndent(clusterPin{
		ClusterPubHex: clusterPubHex,
		Verifier:      verifier,
		TLSSPKIHex:    tlsSPKIHex,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write cluster pin: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename cluster pin: %w", err)
	}
	if tlsSPKIHex != "" {
		b.logf("mesh: cluster pinned with verifier %s + TLS SPKI", verifier)
	} else {
		b.logf("mesh: cluster pinned with verifier %s (no TLS SPKI — server is pre-Phase-B)", verifier)
	}
	// Reinstall the tlsdial hook so control / DERP dials accept
	// the pinned cert without a system trust-store entry.
	b.installClusterSPKIPin()
	return nil
}

// installClusterSPKIPin wires the TLS SPKI pin into tlsdial. Called at
// backend startup after the pin is loaded, and after every successful
// WriteClusterPin. A no-op when no pin is present or the pin predates
// Phase B (TLSSPKIHex empty).
func (b *LocalBackend) installClusterSPKIPin() {
	pin, err := b.loadClusterPin()
	if err != nil || pin == nil || pin.TLSSPKIHex == "" {
		tlsdial.SetSPKIPinMatch(nil)
		return
	}
	want, err := hex.DecodeString(pin.TLSSPKIHex)
	if err != nil || len(want) != sha256.Size {
		tlsdial.SetSPKIPinMatch(nil)
		return
	}
	// Copy into a local to keep the predicate immutable against
	// later mutations of the pin file until the next explicit
	// reinstall.
	fixed := append([]byte(nil), want...)
	tlsdial.SetSPKIPinMatch(func(got []byte) bool {
		return bytes.Equal(got, fixed)
	})
	b.logf("mesh: tlsdial SPKI pin installed (%s…)", pin.TLSSPKIHex[:16])
}

// verifyPeerAgainstPin returns nil iff the peer's NoisePubHex is signed
// by the pinned cluster key. Returns an explicit error when no pin is
// present so the caller can surface "first contact required" instead
// of silently failing over to an unverified server.
func (b *LocalBackend) verifyPeerAgainstPin(peer nmcfg.MeshPeer) error {
	pin, err := b.loadClusterPin()
	if err != nil {
		return err
	}
	if pin == nil {
		return errors.New("no cluster pin installed (run tailscale first-contact with verifier)")
	}
	if peer.NoisePubHex == "" || peer.ClusterSigHex == "" {
		return errors.New("peer has no cluster signature (server side identity not configured)")
	}
	clusterPub, err := hex.DecodeString(pin.ClusterPubHex)
	if err != nil || len(clusterPub) != ed25519.PublicKeySize {
		return fmt.Errorf("pinned cluster pubkey corrupt: %w", err)
	}
	noisePub, err := hex.DecodeString(peer.NoisePubHex)
	if err != nil {
		return fmt.Errorf("peer noise pubkey malformed: %w", err)
	}
	sig, err := hex.DecodeString(peer.ClusterSigHex)
	if err != nil {
		return fmt.Errorf("peer cluster signature malformed: %w", err)
	}
	if !ed25519.Verify(clusterPub, noisePub, sig) {
		return errors.New("peer cluster signature does not verify against pinned cluster key")
	}
	return nil
}

// VerifierFromClusterPubHex recomputes the 8-character short-hash
// verifier of a hex-encoded cluster pubkey. Used at first contact to
// cross-check what the server returned against what the user typed.
// Matches hscontrol/mesh.VerifierFromClusterPub byte-for-byte.
func VerifierFromClusterPubHex(pubHex string) (string, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return "", fmt.Errorf("pubkey hex: %w", err)
	}
	sum := sha256.Sum256(pub)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:5]), nil
}
