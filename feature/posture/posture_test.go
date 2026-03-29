// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package posture

import (
	"errors"
	"os"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tstest"
	"tailscale.com/util/syspolicy/policyclient"
)

func TestCheckPosturePrefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		postureChecking bool
		mockErr         error
		wantErr         string
	}{
		{
			name:            "posture_checking_disabled",
			postureChecking: false,
			mockErr:         nil,
			wantErr:         "",
		},
		{
			name:            "posture_checking_success",
			postureChecking: true,
			mockErr:         nil,
			wantErr:         "",
		},
		// e.g., tailscaled on linux without root or CAP_DAC_READ_SEARCH
		{
			name:            "posture_checking_permissions_error",
			postureChecking: true,
			mockErr:         os.ErrPermission,
			wantErr:         "tailscaled may need to run as root",
		},
		// e.g., on aix, or plan9
		{
			name:            "posture_checking_unsupported",
			postureChecking: true,
			mockErr:         errors.ErrUnsupported,
			wantErr:         "not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tstest.Replace(t, &getSerialNumbers, func(policyclient.Client) ([]string, error) {
				return nil, tt.mockErr
			})

			p := &ipn.Prefs{
				PostureChecking: tt.postureChecking,
			}

			err := checkPosturePrefs(nil, p)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not container %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}
