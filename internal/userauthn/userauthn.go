package userauthn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/sso"

	ldap "github.com/go-ldap/ldap/v3"
)

type Interface interface {
	Authenticate(ctx context.Context, username, password string) bool
}

var (
	ldapDialer       = defaultLdapDialer
	errUserDnMissing = errors.New("userDN missing")
	errConfig        = errors.New("the URL for either LDAP or SSO must be provided")
)

type Implementation struct {
	useLdap bool

	ldapURL       string
	ldapUserDN    string
	ldapTlsConfig *tls.Config //nolint:revive,stylecheck // CamelCase easier to read

	ssoClient sso.Interface
}

func NewUserAuthn(cfg *config.Config) (*Implementation, error) {
	useLdap := false
	var tlsConfig *tls.Config
	var ssoClient sso.Interface

	if cfg.LdapURL != "" {
		useLdap = true
		if cfg.LdapCAFile != "" {
			ldapCaBytes, err := os.ReadFile(cfg.LdapCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA from file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(ldapCaBytes)
			tlsConfig = &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			}
		}

		if cfg.LdapUserDN == "" {
			slog.Error("LdapUserDN must be provided when using LDAP")

			return nil, errUserDnMissing
		}
	} else if cfg.SsoURL != "" {
		ssoClient = sso.NewSsoClient(cfg)
	} else {
		return nil, errConfig
	}

	uan := Implementation{
		useLdap:       useLdap,
		ldapURL:       cfg.LdapURL,
		ldapTlsConfig: tlsConfig,
		ldapUserDN:    cfg.LdapUserDN,
		ssoClient:     ssoClient,
	}

	setupMetrics()

	slog.Info(
		"userauthn.NewUserAuthn",
		"useLdap",
		uan.useLdap,
	)

	return &uan, nil
}

func (uan *Implementation) Authenticate(ctx context.Context, username, password string) bool {
	slog.Debug("userauthn.Authenticate", common.CtxIDLabel, ctx.Value(common.CtxID), "username", username)

	if uan.useLdap {
		return uan.AuthenticateLdap(ctx, username, password)
	}

	return uan.AuthenticateSso(ctx, username, password)
}

func (uan *Implementation) AuthenticateLdap(ctx context.Context, username, password string) bool {
	t0 := time.Now()
	ldapClient, err := uan.getLdapClient()
	t1 := time.Now()
	recordLdapRequest("dial", t1.Sub(t0).Seconds())

	if err != nil {
		recordLdapError("dial")
		slog.Error("failed to connected to LDAP", common.CtxIDLabel, ctx.Value(common.CtxID), "err", err)

		return false
	}
	defer ldapClient.Close()

	userDN := fmt.Sprintf(uan.ldapUserDN, username)
	err = ldapClient.Bind(userDN, password)
	t2 := time.Now()
	recordLdapRequest("bind", t2.Sub(t1).Seconds())
	if err != nil {
		slog.Error("userauthn.AuthenticateLdap bind failed", common.CtxIDLabel, ctx.Value(common.CtxID),
			"userDN", userDN, "err", err)
		recordLdapError("bind")

		return false
	}

	return true
}

func (uan *Implementation) AuthenticateSso(ctx context.Context, username, password string) bool {
	result, _ := uan.ssoClient.Authenticate(ctx, username, password)

	return result
}

func (uan *Implementation) getLdapClient() (ldap.Client, error) {
	ldapDialOpt := make([]ldap.DialOpt, 0, 1)
	if uan.ldapTlsConfig != nil {
		ldapDialOpt = append(ldapDialOpt, ldap.DialWithTLSConfig(uan.ldapTlsConfig))
	}

	return ldapDialer(uan.ldapURL, ldapDialOpt...)
}

func defaultLdapDialer(addr string, opts ...ldap.DialOpt) (ldap.Client, error) {
	return ldap.DialURL(addr, opts...) //nolint:wrapcheck // Ignore as this is to support test
}
