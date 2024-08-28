package sso

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
)

const (
	defaultRequestTimeout        = 30
	defaultDialTimeout           = 5
	defaultIdleConnectionTimeout = 120
	defaultMaxIdleConnections    = 5

	applicationJSON = "application/json"
	requestFailed   = "request failed: %w"

	usernameHeader  = "X-OpenAM-Username"
	passwordReplace = "PASSWORD"
)

var (
	errUnexpectedStatusCode  = errors.New("unexpected status code")
	errUnexpectedContentType = errors.New("unexpected content-type")
	errNoCerts               = errors.New("no certificate provided")
	errCertHost              = errors.New("common name does not match hostname")
	errAuthFailed            = errors.New("sso authenticate failed")
)

type Reply struct {
	TokenID string `json:"tokenId"`
	Message string `json:"message"`
}

type Interface interface {
	Authenticate(ctx context.Context, username, password string) (bool, error)
}

type ClientImpl struct {
	url        string
	httpClient *http.Client
}

func NewSsoClient(cfg *config.Config) *ClientImpl {
	slog.Info("NewSsoClient", "SsoURL", cfg.SsoURL)

	// Validate the URL
	parsedURL, err := url.ParseRequestURI(cfg.SsoURL)
	if err != nil {
		slog.Error("sso.NewSsoClient invalid URL provided for SSO", "url", cfg.SsoURL, "err", err)

		return nil
	}
	ssoHost := parsedURL.Hostname()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.IdleConnTimeout = defaultIdleConnectionTimeout * time.Second
	transport.MaxIdleConns = defaultMaxIdleConnections
	transport.MaxIdleConnsPerHost = defaultMaxIdleConnections

	transport.DialContext = (&net.Dialer{
		Timeout: defaultDialTimeout * time.Second,
	}).DialContext

	if cfg.SsoCAFile != "" {
		tlsConfig, err := getTlsConfig(ssoHost, cfg)
		if err != nil {
			log.Fatal(err)
		}

		transport.TLSClientConfig = tlsConfig
	}

	client := http.Client{
		Timeout:   defaultRequestTimeout * time.Second,
		Transport: common.SetupHttpClientMetrics("sso", transport),
	}

	ci := ClientImpl{
		url:        cfg.SsoURL,
		httpClient: &client,
	}

	return &ci
}

func (ci *ClientImpl) Authenticate(
	ctx context.Context,
	username, password string,
) (bool, error) {
	slog.Debug("sso.Authenticate", common.CtxIDLabel, ctx.Value(common.CtxID),
		"username", username)
	// We've already validated the url so we don't need to look at the err
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, ci.url, http.NoBody)

	request.Header.Add("Accept", applicationJSON)
	request.Header.Add(usernameHeader, username)

	// Need a bit of messing here because we don't want to log the
	// actual URL because it has the password in it
	requestToLog := request.Clone(ctx)
	requestToLog.URL.Path = path.Join(requestToLog.URL.Path, passwordReplace)
	request.URL.Path = path.Join(request.URL.Path, password)

	response, err := ci.httpClient.Do(request)
	if err != nil {
		// Make sure we don't leak the password in the error message
		errMsg := strings.Replace(err.Error(), password, passwordReplace, -1)
		slog.Error("sso.Authenticate Do returned error", common.CtxIDLabel, ctx.Value(common.CtxID),
			"errMsg", errMsg)
		dumpRequestAndResponse(ctx, requestToLog, nil, nil)

		return false, fmt.Errorf("do returned error: %w", err)
	}

	return processResponse(ctx, requestToLog, response)
}

func processResponse(
	ctx context.Context,
	requestToLog *http.Request,
	response *http.Response,
) (bool, error) {
	defer response.Body.Close()
	responseContent, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Error("sso.processResponse error while reading response body", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", requestToLog.Method, "err", err)
		dumpRequestAndResponse(ctx, requestToLog, response, nil)

		return false, fmt.Errorf("error while reading response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		slog.Error("sso.processResponse unexpected status code", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", requestToLog.Method, "status", response.StatusCode)
		dumpRequestAndResponse(ctx, requestToLog, response, responseContent)

		return false, fmt.Errorf("%w: %d", errUnexpectedStatusCode, response.StatusCode)
	}

	slog.Debug("sso.processResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
		"response.StatusCode", response.StatusCode,
		"response.Header", response.Header,
		"responseContent", string(responseContent),
	)

	contentType := response.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, applicationJSON) {
		slog.Error("sso.processResponse unexpected Content-Type", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", requestToLog.Method, "content-type", contentType)
		dumpRequestAndResponse(ctx, requestToLog, response, responseContent)

		return false, fmt.Errorf("%w: %s", errUnexpectedContentType, contentType)
	}

	ssoReply := Reply{}
	err = json.NewDecoder(bytes.NewReader(responseContent)).Decode(&ssoReply)
	if err != nil {
		slog.Error("sso.processResponse decode response body failed", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", requestToLog.Method, "err", err)
		dumpRequestAndResponse(ctx, requestToLog, response, responseContent)

		return false, fmt.Errorf("decode response body failed: %w", err)
	}

	// Seems that if authenication fails we still get a 200 code
	// but the content includes a message with the error.
	if ssoReply.TokenID == "" {
		slog.Warn("sso.processResponse authenication failed", common.CtxIDLabel, ctx.Value(common.CtxID),
			"ssoReply.Message", ssoReply.Message)

		return false, fmt.Errorf("%w: %s", errAuthFailed, ssoReply.Message)
	}

	return true, nil
}

func dumpRequestAndResponse(ctx context.Context,
	request *http.Request,
	response *http.Response, responseData []byte,
) {
	if reqDump, dumpErr := httputil.DumpRequest(request, false); dumpErr == nil {
		slog.Error("sso.dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
			"request", string(reqDump))
	} else {
		slog.Error("sso.dumpRequestAndResponse failed to dump request", "dumpErr", dumpErr)
	}

	if response != nil {
		if respDump, dumpErr := httputil.DumpResponse(response, false); dumpErr == nil {
			slog.Error("sso.dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
				"response", string(respDump))
		} else {
			slog.Error("sso.dumpRequestAndResponse failed to dump response", "dumpErr", dumpErr)
		}
	}

	if responseData != nil {
		slog.Error("sso.dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
			"responseData", string(responseData))
	}
}

//nolint:revive,stylecheck // Easier to read CamelCase
func getTlsConfig(ssoHost string, cfg *config.Config) (*tls.Config, error) {
	caCert, err := os.ReadFile(cfg.SsoCAFile)
	if err != nil {
		return nil, err //nolint:wrapcheck // Error will get wrapped by caller
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caCertPool,
	}

	if cfg.SsoBrokenCA {
		slog.Info("sso.getTlsConfig activating missing SAN workaround")
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // We need to get our VerifyPeerCertificate called
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			slog.Debug("getTlsConfig.VerifyPeerCertificate", "#rawCerts", len(rawCerts))

			if len(rawCerts) == 0 {
				return errNoCerts
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				slog.Error("getTlsConfig.VerifyPeerCertificate ParseCertificate failed", "err", err)

				return err //nolint:wrapcheck // Want to return the orignal error
			}
			slog.Debug("getTlsConfig", "cert.Subject", cert.Subject)

			if _, err := cert.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs}); err != nil {
				slog.Error("getTlsConfig.VerifyPeerCertificate Verify failed", "err", err)

				return err //nolint:wrapcheck // Want to return the orignal error
			}

			if cert.Subject.CommonName != ssoHost {
				err := fmt.Errorf("%w: CommonName=%s SSH Host= %s", errCertHost, cert.Subject.CommonName, ssoHost)
				slog.Error("getTlsConfig.VerifyPeerCertificate Hostname check failed", "err", err)

				return err
			}

			return nil
		}
	}

	return &tlsConfig, nil
}
