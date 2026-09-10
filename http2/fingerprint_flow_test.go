// Copyright 2026 The tlsprint Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	http2 "github.com/lingulingo/tlsprint/http2"
)

// flowBodySize is deliberately larger than the transport's default per-stream
// receive window (4 MiB) and larger than every window a preset advertises.
const flowBodySize = 8 << 20

// newLargeBodyH2Server serves flowBodySize bytes over TLS + HTTP/2.
func newLargeBodyH2Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(flowBodySize))
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < flowBodySize; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// readSlowly drains body, pausing briefly between reads so the consumer lags
// the connection's frame loop. That lag is what exposes a locally enforced
// receive window that is narrower than the advertised one.
func readSlowly(body io.Reader) (int, error) {
	buf := make([]byte, 32<<10)
	total := 0
	for {
		n, err := body.Read(buf)
		total += n
		if n > 0 {
			time.Sleep(time.Millisecond)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// TestFingerprintAdvertisedWindowIsEnforcedLocally guards the invariant that
// the receive window enforced locally covers the window a Fingerprint
// advertises on the wire. When it did not, a peer that legitimately filled the
// advertised window tripped our own accounting and the connection died with a
// spurious FLOW_CONTROL_ERROR partway through a large body.
func TestFingerprintAdvertisedWindowIsEnforcedLocally(t *testing.T) {
	cases := []struct {
		name   string
		window uint32
	}{
		{"chrome-6MiB", 6 << 20},
		{"curl-10MiB", 10 << 20},
		{"okhttp-16MiB", 16 << 20},
		{"safari-4MiB", 4 << 20},
		{"firefox-128KiB", 128 << 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLargeBodyH2Server(t)
			tr := &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Fingerprint: &http2.Fingerprint{
					Settings: []http2.Setting{
						{ID: http2.SettingHeaderTableSize, Val: 65536},
						{ID: http2.SettingEnablePush, Val: 0},
						{ID: http2.SettingInitialWindowSize, Val: tc.window},
						{ID: http2.SettingMaxHeaderListSize, Val: 262144},
					},
				},
			}
			defer tr.CloseIdleConnections()

			req, err := http.NewRequest("GET", srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer resp.Body.Close()

			n, err := readSlowly(resp.Body)
			if err != nil {
				t.Fatalf("read body with advertised window %d: %v after %d/%d bytes", tc.window, err, n, flowBodySize)
			}
			if n != flowBodySize {
				t.Fatalf("read %d bytes, want %d", n, flowBodySize)
			}
		})
	}
}
