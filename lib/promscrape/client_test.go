package promscrape

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/chunkedbuffer"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding/zstd"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/httputil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/promauth"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/proxy"
)

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

type connReadWriteCloser struct {
	io.Reader
	io.WriteCloser
}

func proxyTunnel(w http.ResponseWriter, r *http.Request) {
	transfer := func(src io.ReadCloser, dst io.WriteCloser) {
		defer dst.Close()
		defer src.Close()
		io.Copy(dst, src) //nolint
	}
	server, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	// For hijacked connections, one has to read from the connection buffer, but
	// still write directly to the connection.
	client := &connReadWriteCloser{clientBuf, clientConn}

	go transfer(client, server)
	transfer(server, client)
}

type testProxyServer struct {
	ba                   *promauth.BasicAuthConfig
	receivedProxyRequest bool
}

func checkBasicAuthHeader(w http.ResponseWriter, headerValue string, ba *promauth.BasicAuthConfig) bool {
	userPasswordEncoded := base64.StdEncoding.EncodeToString([]byte(ba.Username + ":" + ba.Password.String()))
	expectedAuthValue := "Basic " + userPasswordEncoded
	if headerValue != expectedAuthValue {
		w.WriteHeader(403)
		fmt.Fprintf(w, "Proxy Requires authorization got header value=%q, want=%q", headerValue, expectedAuthValue)
		return false
	}
	return true
}

func (tps *testProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tps.receivedProxyRequest = true
	if tps.ba != nil {
		if !checkBasicAuthHeader(w, r.Header.Get("Proxy-Authorization"), tps.ba) {
			return
		}
	}
	if r.Method == http.MethodConnect {
		proxyTunnel(w, r)
		return
	}

	tr := httputil.NewTransport(false, "test_client")
	resp, err := tr.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint
}

func newClientTestServer(useTLS bool, rh http.Handler) *httptest.Server {
	var s *httptest.Server
	if useTLS {
		s = httptest.NewTLSServer(rh)
	} else {
		s = httptest.NewServer(rh)
	}
	return s
}

func newTestAuthConfig(t *testing.T, isTLS bool, ba *promauth.BasicAuthConfig) *promauth.Config {
	a := promauth.Options{
		BasicAuth: ba,
	}
	if isTLS {
		a.TLSConfig = &promauth.TLSConfig{InsecureSkipVerify: true}
	}
	ac, err := a.NewConfig()
	if err != nil {
		t.Fatalf("cannot setup promauth.Config: %s", err)
	}
	return ac
}

func TestClientReadDataCompressed(t *testing.T) {
	for _, tc := range []struct {
		encoding string
		compress func(data []byte) []byte
	}{
		{
			encoding: "gzip",
			compress: func(data []byte) []byte {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				if _, err := gz.Write(data); err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				if err := gz.Close(); err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return buf.Bytes()
			},
		},
		{
			encoding: "zstd",
			compress: func(data []byte) []byte {
				return zstd.CompressLevel(nil, data, 1)
			},
		},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			expectedResponse := `metric_name{key="value"} 123` + "\n"
			var gotAcceptEncoding string
			srv := newClientTestServer(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAcceptEncoding = r.Header.Get("Accept-Encoding")
				w.Header().Set("Content-Encoding", tc.encoding)
				_, _ = w.Write(tc.compress([]byte(expectedResponse)))
			}))
			defer srv.Close()

			c, err := newClient(context.Background(), &ScrapeWork{
				ScrapeURL:     srv.URL,
				ScrapeTimeout: 5 * time.Second,
				MaxScrapeSize: 16000,
				AuthConfig:    &promauth.Config{},
			})
			if err != nil {
				t.Fatalf("failed to create client: %s", err)
			}

			var cb chunkedbuffer.Buffer
			contentEncoding, err := c.ReadData(&cb)
			if err != nil {
				t.Fatalf("unexpected error at ReadData: %s", err)
			}
			if contentEncoding != tc.encoding {
				t.Fatalf("unexpected Content-Encoding: got %q, want %q", contentEncoding, tc.encoding)
			}
			if gotAcceptEncoding != "zstd, gzip;q=0.5" {
				t.Fatalf("unexpected Accept-Encoding sent to the target: got %q, want %q", gotAcceptEncoding, "zstd, gzip;q=0.5")
			}
			// decompress the downloaded data the same way as scrapeWork does
			var bb bytesutil.ByteBuffer
			sw := &scrapeWork{
				Config: &ScrapeWork{
					ScrapeURL:     srv.URL,
					MaxScrapeSize: 16000,
				},
			}
			if err := sw.readFromBuffer(&bb, &cb, contentEncoding); err != nil {
				t.Fatalf("unexpected error in readFromBuffer: %s", err)
			}
			if string(bb.B) != expectedResponse {
				t.Fatalf("unexpected uncompressed response: got %q, want %q", bb.B, expectedResponse)
			}
		})
	}
}

func TestClientProxyReadOk(t *testing.T) {
	ctx := context.Background()
	f := func(isBackendTLS, isProxyTLS bool, backendAuth, proxyAuth *promauth.BasicAuthConfig) {
		t.Helper()

		proxyHandler := &testProxyServer{ba: proxyAuth}
		ps := newClientTestServer(isProxyTLS, proxyHandler)

		expectedBackendResponse := `metric_name{key="value"} 123\n`

		backend := newClientTestServer(isBackendTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if backendAuth != nil && !checkBasicAuthHeader(w, r.Header.Get("Authorization"), backendAuth) {
				return
			}
			w.Write([]byte(expectedBackendResponse))
		}))

		defer backend.Close()
		defer ps.Close()

		c, err := newClient(ctx, &ScrapeWork{
			ScrapeURL: backend.URL,
			ProxyURL:  proxy.MustNewURL(ps.URL),
			// bump timeout for slow CIs
			ScrapeTimeout: 5 * time.Second,
			// force connection re-creating to avoid broken conns in slow CIs
			DisableKeepAlive:   true,
			AuthConfig:         newTestAuthConfig(t, isBackendTLS, backendAuth),
			ProxyAuthConfig:    newTestAuthConfig(t, isProxyTLS, proxyAuth),
			MaxScrapeSize:      16000,
			DisableCompression: true,
		})
		if err != nil {
			t.Fatalf("failed to create client: %s", err)
		}

		var cb chunkedbuffer.Buffer
		contentEncoding, err := c.ReadData(&cb)
		if err != nil {
			t.Fatalf("unexpected error at ReadData: %s", err)
		}
		if contentEncoding != "" {
			t.Fatalf("the response mustn't be compressed; got Content-Encoding=%q", contentEncoding)
		}
		got, err := io.ReadAll(cb.NewReader())
		if err != nil {
			t.Fatalf("err read: %s", err)
		}

		if !proxyHandler.receivedProxyRequest {
			t.Fatalf("proxy server didn't received request")
		}
		if string(got) != expectedBackendResponse {
			t.Fatalf("not expected response: ")
		}
	}

	// no tls
	f(false, false, nil, nil)
	// both tls no auth
	f(true, true, nil, nil)
	// backend tls, proxy http no auth
	f(true, false, nil, nil)
	// backend http, proxy tls no auth
	f(false, true, nil, nil)

	// no tls with auth
	f(false, false, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, &promauth.BasicAuthConfig{Username: "proxy-test"})
	// proxy tls and auth
	f(false, true, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, &promauth.BasicAuthConfig{Username: "proxy-test"})
	// backend tls and auth
	f(true, false, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, &promauth.BasicAuthConfig{Username: "proxy-test"})
	// tls with auth
	f(true, true, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, &promauth.BasicAuthConfig{Username: "proxy-test"})

	// tls with backend auth
	f(true, true, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, nil)
	// tls with proxy auth
	f(true, true, nil, &promauth.BasicAuthConfig{Username: "proxy-test", Password: promauth.NewSecret("1234")})
	// proxy tls with backend auth
	f(false, true, &promauth.BasicAuthConfig{Username: "test", Password: promauth.NewSecret("1234")}, nil)
	// backend tls and proxy auth
	f(true, false, nil, &promauth.BasicAuthConfig{Username: "proxy-test", Password: promauth.NewSecret("1234")})
}
