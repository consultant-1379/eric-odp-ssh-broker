package userauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
)

const (
	CaFile = "/ca.crt"
)

type ldapTestResult struct {
	err error
}
type LdapTestClient struct {
	results []ldapTestResult
}

var (
	errDialFailed = errors.New("dial Failed")
	errBindFailed = errors.New("bind for user failed")
	testCtx       = context.WithValue(context.TODO(), common.CtxID, "test")
	testLdap      *LdapTestClient
)

func TestMain(m *testing.M) {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))

	ldapDialer = testDialer
	os.Exit(m.Run())
}

//nolint:unparam // Ignore, will change when we implement SSO
func createUserAuthn(t *testing.T, useLdap, useTLS bool) *Implementation {
	cfg := config.Config{}

	if useLdap {
		cfg.LdapURL = "ldap://localhost"
		cfg.LdapUserDN = "cn=%s,ou=users,dc=example,dc=org"

		if useTLS {
			ldapCaDDir := t.TempDir()

			// Create CA
			ca := &x509.Certificate{
				SerialNumber: big.NewInt(2019),
				Subject: pkix.Name{
					Country:            []string{"SE"},
					Organization:       []string{"Ericsson"},
					OrganizationalUnit: []string{"OSS"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(10, 0, 0),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				BasicConstraintsValid: true,
			}
			// create our private and public key
			caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				panic(err)
			}

			// create the CA
			caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
			if err != nil {
				panic(err)
			}

			// pem encode
			caPEM := new(bytes.Buffer)
			pem.Encode(caPEM, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caBytes,
			})
			cfg.LdapCAFile = ldapCaDDir + CaFile
			err = os.WriteFile(cfg.LdapCAFile, caPEM.Bytes(), 0o600)
			if err != nil {
				panic(err)
			}
		}
	}

	uan, newError := NewUserAuthn(&cfg)
	if newError != nil {
		t.Fatalf("TestLdapOkay: got unexpected error calling NewUserAuthn %v", newError)
	}

	return uan
}

func TestLdapOkay(t *testing.T) {
	uan := createUserAuthn(t, true, false)

	testLdap = &LdapTestClient{}

	gotResult := uan.Authenticate(testCtx, "testuser", "testpassword")
	expectedResult := true

	if gotResult != expectedResult {
		t.Error("Expected Authenticate to succeed")
	}
}

func TestLdapDialFailure(t *testing.T) {
	uan := createUserAuthn(t, true, false)

	testLdap = nil // Set testLdap to simulate ldap dial error

	gotResult := uan.Authenticate(testCtx, "testuser", "testpassword")
	expectedResult := false

	if gotResult != expectedResult {
		t.Error("Expected Authenticate to fail")
	}
}

func TestLdapBindFailure(t *testing.T) {
	uan := createUserAuthn(t, true, false)

	testLdap = &LdapTestClient{results: []ldapTestResult{{err: errBindFailed}}}

	gotResult := uan.Authenticate(testCtx, "testuser", "testpassword")
	expectedResult := false

	if gotResult != expectedResult {
		t.Error("Expected Authenticate to fail")
	}
}

func TestLdapTLSOkay(t *testing.T) {
	uan := createUserAuthn(t, true, true)

	testLdap = &LdapTestClient{}

	gotResult := uan.Authenticate(testCtx, "testuser", "testpassword")
	expectedResult := true

	if gotResult != expectedResult {
		t.Error("Expected Authenticate to succeed")
	}
}

func testDialer(_ string, _ ...ldap.DialOpt) (ldap.Client, error) {
	if testLdap == nil {
		return nil, errDialFailed
	}

	return testLdap, nil
}

func (ltc *LdapTestClient) Start() {}

func (ltc *LdapTestClient) StartTLS(*tls.Config) error {
	return nil
}

func (ltc *LdapTestClient) Close() error {
	return nil
}

func (ltc *LdapTestClient) GetLastError() error {
	return nil
}

func (ltc *LdapTestClient) IsClosing() bool {
	return false
}

func (ltc *LdapTestClient) SetTimeout(time.Duration) {}

func (ltc *LdapTestClient) TLSConnectionState() (tls.ConnectionState, bool) {
	return tls.ConnectionState{}, false
}

func (ltc *LdapTestClient) Bind(_, _ string) error {
	if len(ltc.results) > 0 {
		return ltc.results[0].err
	}

	return nil
}

func (ltc *LdapTestClient) UnauthenticatedBind(_ string) error {
	return nil
}

func (ltc *LdapTestClient) SimpleBind(*ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	return nil, nil
}

func (ltc *LdapTestClient) ExternalBind() error {
	return nil
}

func (ltc *LdapTestClient) NTLMUnauthenticatedBind(_, _ string) error {
	return nil
}

func (ltc *LdapTestClient) Unbind() error {
	return nil
}

func (ltc *LdapTestClient) Add(*ldap.AddRequest) error {
	return nil
}

func (ltc *LdapTestClient) Del(*ldap.DelRequest) error {
	return nil
}

func (ltc *LdapTestClient) Modify(*ldap.ModifyRequest) error {
	return nil
}

func (ltc *LdapTestClient) ModifyDN(*ldap.ModifyDNRequest) error {
	return nil
}

func (ltc *LdapTestClient) ModifyWithResult(*ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	return nil, nil
}

func (ltc *LdapTestClient) Compare(_, _, _ string) (bool, error) {
	return false, nil
}

func (ltc *LdapTestClient) PasswordModify(_ *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, nil
}

func (ltc *LdapTestClient) Search(_ *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return nil, nil
}

func (ltc *LdapTestClient) SearchAsync(_ context.Context, _ *ldap.SearchRequest, _ int) ldap.Response {
	return nil
}

func (ltc *LdapTestClient) SearchWithPaging(_ *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return nil, nil
}

func (ltc *LdapTestClient) DirSync(_ *ldap.SearchRequest, _, _ int64, _ []byte) (*ldap.SearchResult, error) {
	return nil, nil
}

//nolint:lll // Suppress long line
func (ltc *LdapTestClient) DirSyncAsync(_ context.Context, _ *ldap.SearchRequest, _ int, _, _ int64, _ []byte) ldap.Response {
	return nil
}

//nolint:lll // Suppress long line
func (ltc *LdapTestClient) Syncrepl(_ context.Context, _ *ldap.SearchRequest, _ int, _ ldap.ControlSyncRequestMode, _ []byte, _ bool) ldap.Response {
	return nil
}
