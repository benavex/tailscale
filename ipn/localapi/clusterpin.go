// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Localapi endpoint for cluster-pin first contact. Fetches
// /mesh/identity from a user-supplied bootstrap URL, verifies the
// returned cluster pubkey hashes to the user-supplied verifier, checks
// the ed25519 signature over the bootstrap server's noise pubkey, and
// persists the pin via LocalBackend.WriteClusterPin.
//
// After a successful call, meshFailover rotations will only accept
// sibling control servers whose noise pubkey carries a valid
// cluster-signed entry in the MeshSnapshot — defeating the DNS
// poisoning and rogue-sibling attacks that motivated todo 1d.

package localapi

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/httpm"
)

func init() {
	Register("cluster-pin", (*Handler).serveClusterPin)
}

type clusterPinRequest struct {
	BootstrapURL string `json:"bootstrap_url"`
	Verifier     string `json:"verifier"`
}

type clusterPinResponse struct {
	Verifier   string `json:"verifier"`
	ClusterPub string `json:"cluster_pub"`
}

type serverIdentityResponse struct {
	ClusterPub string `json:"cluster_pub"`
	NoisePub   string `json:"noise_pub"`
	Signature  string `json:"signature"`
	Verifier   string `json:"verifier"`
}

// serveClusterPin is the first-contact handler. Input:
//
//	POST /localapi/v0/cluster-pin
//	{"bootstrap_url": "https://hs42.duckdns.org",
//	 "verifier":      "ABC23XYZ"}
//
// On success, writes the pin and returns 200 with the canonical
// cluster pubkey + verifier. Idempotent: re-posting the same pub is a
// no-op. Re-posting a different pub fails with 409 Conflict.
func (h *Handler) serveClusterPin(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "cluster-pin access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusMethodNotAllowed)
		return
	}
	var req clusterPinRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.Verifier = strings.ToUpper(strings.TrimSpace(req.Verifier))
	req.BootstrapURL = strings.TrimRight(strings.TrimSpace(req.BootstrapURL), "/")
	if req.BootstrapURL == "" || req.Verifier == "" {
		http.Error(w, "bootstrap_url and verifier are both required", http.StatusBadRequest)
		return
	}
	if len(req.Verifier) != 8 {
		http.Error(w, "verifier must be exactly 8 characters", http.StatusBadRequest)
		return
	}

	clusterPub, err := firstContactFetch(r.Context(), req.BootstrapURL, req.Verifier)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	if err := h.b.WriteClusterPin(clusterPub, req.Verifier); err != nil {
		if strings.Contains(err.Error(), "pin mismatch") {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "persist pin: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(clusterPinResponse{
		Verifier:   req.Verifier,
		ClusterPub: clusterPub,
	})
}

// firstContactFetch runs the network + crypto side of the pin flow
// without touching disk. Returns the hex-encoded cluster pubkey on
// success. Separate function so it's unit-testable without the
// LocalBackend dependency.
func firstContactFetch(ctx context.Context, bootstrapURL, verifier string) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL+"/mesh/identity", nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("fetch %s/mesh/identity: %w", bootstrapURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("bootstrap server has no cluster identity configured — set cluster_secret on the server")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bootstrap returned %s", resp.Status)
	}
	var ident serverIdentityResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&ident); err != nil {
		return "", fmt.Errorf("decode identity: %w", err)
	}
	clusterPubBytes, err := hex.DecodeString(ident.ClusterPub)
	if err != nil || len(clusterPubBytes) != ed25519.PublicKeySize {
		return "", errors.New("bootstrap returned malformed cluster pubkey")
	}
	noisePubBytes, err := hex.DecodeString(ident.NoisePub)
	if err != nil {
		return "", errors.New("bootstrap returned malformed noise pubkey")
	}
	sigBytes, err := hex.DecodeString(ident.Signature)
	if err != nil {
		return "", errors.New("bootstrap returned malformed signature")
	}

	got, err := ipnlocal.VerifierFromClusterPubHex(ident.ClusterPub)
	if err != nil {
		return "", fmt.Errorf("derive verifier: %w", err)
	}
	if !strings.EqualFold(got, verifier) {
		return "", fmt.Errorf("verifier mismatch: server claims %q, you entered %q — possible MITM, refusing to pin",
			got, verifier)
	}
	if !ed25519.Verify(clusterPubBytes, noisePubBytes, sigBytes) {
		return "", errors.New("bootstrap server's noise pubkey is not signed by its cluster key — refusing to pin")
	}
	return ident.ClusterPub, nil
}
