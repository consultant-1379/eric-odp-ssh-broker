package factory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/dirwatcher"
	"eric-odp-ssh-broker/internal/testcommon"
)

const (
	expectedTokenName    = "name"
	expectedTokenDataKey = "name1"
	expectedTokenDataVal = "val1"
	hdrContentType       = "Content-Type"
)

var (
	testCtx       = context.WithValue(context.TODO(), common.CtxID, "test")
	creatingReply = []byte("{\"podname\": \"eric-odp-testapp-01234\", \"resultcode\": -1}")
	readyReply    = []byte("{\"podname\": \"eric-odp-testapp-01234\", \"resultcode\": 0, \"podips\": [ \"1.2.3.4\" ] }")
)

type httpTestHandlerState struct {
	t             *testing.T
	replyHandlers []func(http.ResponseWriter, *http.Request)
	index         int
}

type httpdHandler struct {
	state *httpTestHandlerState
}

func (h httpdHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.state.t.Errorf("Expected to method %s, got: %s", http.MethodPost, r.Method)
	}
	expectedPath := "/odp/"
	if r.URL.Path != expectedPath {
		h.state.t.Errorf("Expected to request %s, got: %s", expectedPath, r.URL.Path)
	}
	if r.Header.Get("Accept") != applicationJSON {
		h.state.t.Errorf("Expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
	}

	h.state.replyHandlers[h.state.index](w, r)
	h.state.index++
}

func TestMain(m *testing.M) {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	os.Exit(m.Run())
}

func TestGetOdpOkay(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, creatingReply)
				},
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, readyReply)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	cfg := config.Config{FactoryURL: server.URL + "/odp/", FactoryMaxRequests: 2, FactoryRequestInterval: 1}

	fci := NewFactoryClient(&cfg)

	fci.requestInterval = time.Microsecond

	odpReply, err := fci.GetOdp(testCtx, "testuser", "testapp", []string{"sso"})
	t.Logf("odpReply: %v", odpReply)
	if err != nil {
		t.Errorf("unexpected error from GetOdp: %v", err)
	} else if odpReply.ResultCode != 0 {
		t.Errorf("unexpected result code from GetOdp: %v", odpReply)
	}
}

func TestTLS(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, creatingReply)
				},
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, readyReply)
				},
			},
		},
	}
	server := httptest.NewUnstartedServer(handler)

	certDir := t.TempDir()
	caCert, caKey := testcommon.CreateCertPair(t, "factoryca", true, nil, nil, certDir)
	testcommon.CreateCertPair(t, "factory", false, caCert, caKey, certDir)

	serverTLSCert, _ := tls.LoadX509KeyPair(certDir+"/factory/tls.crt", certDir+"/factory/tls.key")
	certPool := x509.NewCertPool()
	caCertPEM, err := os.ReadFile(certDir + "/factoryca/tls.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(caCertPEM)
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Logf("server URL: %s", server.URL)

	testcommon.CreateCertPair(t, "trustedclient", false, caCert, caKey, certDir)

	dirwatcher.Start()

	cfg := config.Config{
		FactoryURL:      server.URL + "/odp/",
		FactoryCAFile:   certDir + "/factoryca/tls.crt",
		FactoryCertFile: certDir + "/trustedclient/tls.crt",
		FactoryKeyFile:  certDir + "/trustedclient/tls.key",

		FactoryMaxRequests:     2,
		FactoryRequestInterval: 1,
	}

	fci := NewFactoryClient(&cfg)

	fci.requestInterval = time.Microsecond

	odpReply, err := fci.GetOdp(testCtx, "testuser", "testapp", []string{"sso"})
	t.Logf("odpReply: %v", odpReply)
	if err != nil {
		t.Errorf("unexpected error from GetOdp: %v", err)
	} else if odpReply.ResultCode != 0 {
		t.Errorf("unexpected result code from GetOdp: %v", odpReply)
	}

	dirwatcher.Stop()
}

// Test where Content-Type includes trailing info, e.g. "application/json; charset=UTF-8".
func TestGetOkayContentType(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON+"; charset=UTF-8", http.StatusOK, creatingReply)
				},
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON+"; charset=UTF-8", http.StatusOK, readyReply)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	cfg := config.Config{FactoryURL: server.URL + "/odp/", FactoryMaxRequests: 2, FactoryRequestInterval: 1}

	fci := NewFactoryClient(&cfg)

	fci.requestInterval = time.Microsecond

	odpReply, err := fci.GetOdp(testCtx, "testuser", "testapp", []string{"sso"})
	t.Logf("odpReply: %v", odpReply)
	if err != nil {
		t.Errorf("unexpected error from GetOdp: %v", err)
	} else if odpReply.ResultCode != 0 {
		t.Errorf("unexpected result code from GetOdp: %v", odpReply)
	}
}

func TestOkayStatusCode(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusInternalServerError, nil)
				},
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, creatingReply)
				},
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, readyReply)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	cfg := config.Config{FactoryURL: server.URL + "/odp/", FactoryMaxRequests: 3, FactoryRequestInterval: 1}

	fci := NewFactoryClient(&cfg)

	fci.requestInterval = time.Microsecond

	odpReply, err := fci.GetOdp(testCtx, "testuser", "testapp", []string{"sso"})
	t.Logf("odpReply: %v", odpReply)
	if err != nil {
		t.Errorf("unexpected error from GetOdp: %v", err)
	} else if odpReply.ResultCode != 0 {
		t.Errorf("unexpected result code from GetOdp: %v", odpReply)
	}
}

func TestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(time.Millisecond * 100)
	}))
	defer server.Close()

	cfg := config.Config{FactoryURL: server.URL + "/odp/", FactoryMaxRequests: 1, FactoryRequestInterval: 1}
	fci := NewFactoryClient(&cfg)
	fci.httpClient.Timeout = time.Microsecond
	verifyTimeoutErrorForFci(fci, t)
}

func TestFailInvalidURL(t *testing.T) {
	verifyTimeoutError("blah blah blah", t)
}

func TestFailBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add(hdrContentType, applicationJSON)
		w.Header().Add("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	verifyTimeoutError(server.URL, t)
}

func TestFailContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		srvWriteResponseContentType(w, "plain/text", http.StatusOK, nil)
	}))
	defer server.Close()

	verifyTimeoutError(server.URL, t)
}

func TestFailInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		srvWriteResponseContentType(w, applicationJSON, http.StatusOK, []byte("not JSON"))
	}))
	defer server.Close()

	verifyTimeoutError(server.URL, t)
}

func srvWriteResponseContentType(w http.ResponseWriter, contentType string, status int, content []byte) {
	if contentType != "" {
		w.Header().Add(hdrContentType, contentType)
	}

	w.WriteHeader(status)

	if content != nil {
		w.Write(content)
	}
}

func verifyTimeoutError(baseURL string, t *testing.T) {
	cfg := config.Config{FactoryURL: baseURL + "/odp/", FactoryMaxRequests: 1, FactoryRequestInterval: 1}
	fci := NewFactoryClient(&cfg)
	verifyTimeoutErrorForFci(fci, t)
}

func verifyTimeoutErrorForFci(fci *ClientImpl, t *testing.T) {
	odpReply, err := fci.GetOdp(testCtx, "testuser", "testapp", []string{"sso"})
	t.Logf("odpReply: %v", odpReply)
	if err == nil {
		t.Errorf("expected error from GetOdp: %v", odpReply)
	} else if err.Error() != errTimedOut.Error() {
		t.Errorf("expected err %v from GetOdp, got %v", errTimedOut, err)
	}
}
