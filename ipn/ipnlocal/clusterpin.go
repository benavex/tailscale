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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"tailscale.com/wgengine/wgcfg/nmcfg"
)

// clusterPinFile is the on-disk name of the pin. Lives directly under
// varRoot so it's one file per machine, not per-profile — rotating
// user accounts must not drop the trust anchor.
const clusterPinFile = "clusterpin.json"

// clusterPin is the on-disk record. Only the cluster pubkey is
// load-bearing; the verifier string is stored purely for debugging.
type clusterPin struct {
	ClusterPubHex string `json:"cluster_pub"`
	Verifier      string `json:"verifier"`
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

// WriteClusterPin records the cluster pubkey + verifier. Idempotent:
// overwriting with the same pub+verifier is a no-op; overwriting with
// a different pub returns an error so an operator sees an explicit
// "pin mismatch" rather than silent re-pinning. To force a change, the
// user must delete the file out of band (documented as a factory reset).
func (b *LocalBackend) WriteClusterPin(clusterPubHex, verifier string) error {
	path := b.clusterPinPath()
	if path == "" {
		return errors.New("no var root configured; cannot persist cluster pin")
	}
	if got, _ := hex.DecodeString(clusterPubHex); len(got) != ed25519.PublicKeySize {
		return fmt.Errorf("cluster pubkey hex decodes to %d bytes, want %d",
			len(got), ed25519.PublicKeySize)
	}
	if existing, err := b.loadClusterPin(); err != nil {
		return err
	} else if existing != nil {
		if existing.ClusterPubHex == clusterPubHex {
			return nil
		}
		return fmt.Errorf("cluster pin mismatch: pinned=%s attempted=%s (factory-reset to change)",
			existing.Verifier, verifier)
	}
	tmp := path + ".tmp"
	raw, err := json.MarshalIndent(clusterPin{
		ClusterPubHex: clusterPubHex,
		Verifier:      verifier,
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
	b.logf("mesh: cluster pinned with verifier %s", verifier)
	return nil
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
