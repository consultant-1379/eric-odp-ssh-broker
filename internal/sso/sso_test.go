package sso

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/testcommon"
)

const (
	expectedTokenName    = "name"
	expectedTokenDataKey = "name1"
	expectedTokenDataVal = "val1"
	hdrContentType       = "Content-Type"
)

var (
	testCtx         = context.WithValue(context.TODO(), common.CtxID, "test")
	ssoReplyContent = []byte("{\"tokenId\": \"tk1234\"}")
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
	expectedPath := "/pam/authenticate/thepassword"
	if r.URL.Path != expectedPath {
		h.state.t.Errorf("Expected to request %s, got: %s", expectedPath, r.URL.Path)
	}
	if r.Header.Get("Accept") != applicationJSON {
		h.state.t.Errorf("Expected Accept: application/json header, got: %s", r.Header.Get("Accept"))
	}
	if r.Header.Get(usernameHeader) != "testuser" {
		h.state.t.Errorf("Unexpected value for user name heade3r : got: %s", r.Header.Get(usernameHeader))
	}

	h.state.replyHandlers[h.state.index](w, r)
	h.state.index++
}

func TestMain(m *testing.M) {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	os.Exit(m.Run())
}

func TestAuthenciateOkay(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, ssoReplyContent)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	cfg := config.Config{SsoURL: server.URL + "/pam/authenticate/"}

	sci := NewSsoClient(&cfg)

	result, err := sci.Authenticate(testCtx, "testuser", "thepassword")
	if err != nil {
		t.Errorf("unexpected error from Authenticate: %v", err)
	} else if !result {
		t.Errorf("unexpected result Authenticate: %t", result)
	}
}

func TestNoPortInURL(t *testing.T) {
	cfg := config.Config{SsoURL: "http://localhost/pam/authenticate/"}
	sci := NewSsoClient(&cfg)
	if sci == nil {
		t.Error("Failed to handle SSO URL without port number")
	}
}

func TestTLS(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, ssoReplyContent)
				},
			},
		},
	}
	server := httptest.NewUnstartedServer(handler)

	certDir := t.TempDir()
	caCert, caKey := testcommon.CreateCertPair(t, "ssoca", true, nil, nil, certDir)
	testcommon.CreateCertPair(t, "sso", false, caCert, caKey, certDir)

	serverTLSCert, _ := tls.LoadX509KeyPair(certDir+"/sso/tls.crt", certDir+"/sso/tls.key")
	certPool := x509.NewCertPool()
	caCertPEM, err := os.ReadFile(certDir + "/ssoca/tls.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(caCertPEM)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Logf("server URL: %s", server.URL)

	cfg := config.Config{
		SsoURL:    server.URL + "/pam/authenticate/",
		SsoCAFile: certDir + "/ssoca/tls.crt",
	}

	sci := NewSsoClient(&cfg)

	result, err := sci.Authenticate(testCtx, "testuser", "thepassword")
	if err != nil {
		t.Errorf("unexpected error from Authenticate: %v", err)
	} else if !result {
		t.Errorf("unexpected result Authenticate: %t", result)
	}
}

func TestTLSnoSAN(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, ssoReplyContent)
				},
			},
		},
	}
	server := httptest.NewUnstartedServer(handler)

	certDir := t.TempDir()
	t.Logf("TestTLSnoSAN certDir=%s", certDir)
	caCert, caKey := testcommon.CreateCertPair(t, "ssoca", true, nil, nil, certDir)
	serverCertName := "127.0.0.1"
	testcommon.CreateCertPairOpts(t, serverCertName, false, caCert, caKey, certDir, false)
	serverTLSCert, _ := tls.LoadX509KeyPair(certDir+"/"+serverCertName+"/tls.crt", certDir+"/"+serverCertName+"/tls.key")
	certPool := x509.NewCertPool()
	caCertPEM, err := os.ReadFile(certDir + "/ssoca/tls.crt")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(caCertPEM)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()

	t.Logf("server URL: %s", server.URL)

	cfg := config.Config{
		SsoURL:    server.URL + "/pam/authenticate/",
		SsoCAFile: certDir + "/ssoca/tls.crt",
	}
	sci := NewSsoClient(&cfg)

	expectedErrMsg := "certificate relies on legacy Common Name field, use SANs instead"
	_, err = sci.Authenticate(testCtx, "testuser", "thepassword")
	if err == nil {
		t.Fatal("expected error from Authenticate")
	} else if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("expected err message to contain \"%s\", got %v", expectedErrMsg, err)
	}

	// Now repeat with SsoBrokenCA set
	cfg = config.Config{
		SsoURL:      server.URL + "/pam/authenticate/",
		SsoCAFile:   certDir + "/ssoca/tls.crt",
		SsoBrokenCA: true,
	}
	sci = NewSsoClient(&cfg)

	result, err := sci.Authenticate(testCtx, "testuser", "thepassword")
	if err != nil {
		t.Errorf("unexpected error from Authenticate: %v", err)
	} else if !result {
		t.Errorf("unexpected result Authenticate: %t", result)
	}
}

func TestNotOkayWrongPassword(t *testing.T) {
	authFailed := []byte("{\"message\":\"<title>OpenAM (Authentication Failed)</title><h3>Authentication failed.</h3>\"}")
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusOK, authFailed)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	verifyFail(server.URL, t)
}

func TestNotOkayStatusCode(t *testing.T) {
	handler := httpdHandler{
		state: &httpTestHandlerState{
			t: t,
			replyHandlers: []func(http.ResponseWriter, *http.Request){
				func(w http.ResponseWriter, _ *http.Request) {
					srvWriteResponseContentType(w, applicationJSON, http.StatusInternalServerError, nil)
				},
			},
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	verifyFail(server.URL, t)
}

func TestFailInvalidURL(t *testing.T) {
	cfg := config.Config{SsoURL: "blah blah blah" + "/pam/authenticate/"}
	sci := NewSsoClient(&cfg)
	if sci != nil {
		t.Fatal("expected nil return due to invalid URL")
	}
}

func TestFailBodyRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add(hdrContentType, applicationJSON)
		w.Header().Add("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	verifyFail(server.URL, t)
}

func TestFailContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		srvWriteResponseContentType(w, "plain/text", http.StatusOK, nil)
	}))
	defer server.Close()

	verifyFail(server.URL, t)
}

func TestFailInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		srvWriteResponseContentType(w, applicationJSON, http.StatusOK, []byte("not JSON"))
	}))
	defer server.Close()

	verifyFail(server.URL, t)
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

func verifyFail(baseURL string, t *testing.T) {
	cfg := config.Config{SsoURL: baseURL + "/pam/authenticate/"}

	sci := NewSsoClient(&cfg)
	result, err := sci.Authenticate(testCtx, "testuser", "thepassword")

	if err == nil {
		t.Error("expected error from Authenticate")
	} else if result {
		t.Errorf("unexpected result from Authenticate: %t", result)
	}
}
