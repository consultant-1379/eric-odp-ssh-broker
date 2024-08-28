package factory

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
	"os"
	"path/filepath"
	"strings"
	"time"

	"eric-odp-ssh-broker/internal/certwatcher"
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

	OdpCreating = -1
	OdpReady    = 0
)

var (
	errUnexpectedStatusCode  = errors.New("unexpected status code")
	errUnexpectedContentType = errors.New("unexpected content-type")
	errTimedOut              = errors.New("timeout out wait for ODP to be ready")
	errOdpErr                = errors.New("odp err")
)

type OnDemandPodRequest struct {
	UserName    string            `json:"username"`
	Application string            `json:"application"`
	TokenTypes  []string          `json:"tokentypes"`
	Data        map[string]string `json:"data"`
	InstanceID  string            `json:"instanceid"`
}

type OnDemandPodReply struct {
	PodName    string            `json:"podname"`
	ResultCode int               `json:"resultcode"`
	TokenData  map[string]string `json:"tokendata"`
	PodIPs     []string          `json:"podips"`
	Error      string            `json:"error"`
}

type Interface interface {
	GetOdp(ctx context.Context, username, application string, tokentypes []string) (*OnDemandPodReply, error)
}

type ClientImpl struct {
	url             string
	httpClient      *http.Client
	maxRequests     int
	requestInterval time.Duration
}

func NewFactoryClient(cfg *config.Config) *ClientImpl {
	slog.Info("NewFactoryClient", "FactoryURL", cfg.FactoryURL)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.IdleConnTimeout = defaultIdleConnectionTimeout * time.Second
	transport.MaxIdleConns = defaultMaxIdleConnections
	transport.MaxIdleConnsPerHost = defaultMaxIdleConnections

	if cfg.FactoryCAFile != "" {
		transport.DialContext = (&net.Dialer{
			Timeout: defaultDialTimeout * time.Second,
		}).DialContext

		fullpath, _ := filepath.Abs(cfg.FactoryCertFile)
		certDir := filepath.Dir(fullpath)
		certFileName := filepath.Base(cfg.FactoryCertFile)
		certKeyName := filepath.Base(cfg.FactoryKeyFile)
		certWatcher := certwatcher.NewWatcher(certDir, certFileName, certKeyName)

		caCert, err := os.ReadFile(cfg.FactoryCAFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig := tls.Config{
			MinVersion:           tls.VersionTLS12,
			GetClientCertificate: certWatcher.GetClientCertificate,
			RootCAs:              caCertPool,
		}
		transport.TLSClientConfig = &tlsConfig
	} else {
		transport.DialContext = (&net.Dialer{
			Timeout: defaultDialTimeout * time.Second,
		}).DialContext
	}

	client := http.Client{
		Timeout:   defaultRequestTimeout * time.Second,
		Transport: common.SetupHttpClientMetrics("factory", transport),
	}

	fci := ClientImpl{
		url:             cfg.FactoryURL,
		maxRequests:     cfg.FactoryMaxRequests,
		requestInterval: time.Millisecond * time.Duration(cfg.FactoryRequestInterval),
		httpClient:      &client,
	}

	return &fci
}

func (fci *ClientImpl) GetOdp(
	ctx context.Context,
	username, application string,
	tokentypes []string,
) (*OnDemandPodReply, error) {
	slog.Info("GetOdp", common.CtxIDLabel, ctx.Value(common.CtxID),
		"username", username, "application", application, "tokentypes", tokentypes)

	requestData := OnDemandPodRequest{
		UserName:    username,
		Application: application,
		TokenTypes:  tokentypes,
	}
	jsonData, _ := json.Marshal(requestData)

	requestCount := 0
	for requestCount < fci.maxRequests {
		requestCount++
		slog.Debug("GetOdp", common.CtxIDLabel, ctx.Value(common.CtxID), "requestCount", requestCount)

		odpReply, err := fci.doRequest(ctx, http.MethodPost, jsonData)
		if err != nil {
			slog.Error("GetOdp request failed", common.CtxIDLabel, ctx.Value(common.CtxID),
				"username", username, "application", application, "tokentypes", tokentypes, "err", err)
		}
		if err != nil || odpReply.ResultCode == OdpCreating {
			time.Sleep(fci.requestInterval)
		} else {
			slog.Debug("GetOdp", common.CtxIDLabel, ctx.Value(common.CtxID), "odpReply", odpReply)
			if odpReply.ResultCode > OdpReady {
				slog.Error("GetOdp Odp Error", common.CtxIDLabel, ctx.Value(common.CtxID),
					"username", username, "application", application, "tokentypes", tokentypes, "odp.Error", odpReply.Error)

				return nil, fmt.Errorf("%w: %s", errOdpErr, odpReply.Error)
			}
			slog.Info("GetOdp", common.CtxIDLabel, ctx.Value(common.CtxID), "PodName", odpReply.PodName)

			return odpReply, nil
		}
	}

	return nil, errTimedOut
}

func (fci *ClientImpl) doRequest(
	ctx context.Context,
	method string,
	data []byte,
) (*OnDemandPodReply, error) {
	var requestBody io.Reader
	if data != nil {
		requestBody = bytes.NewReader(data)
	} else {
		requestBody = http.NoBody
	}
	request, err := http.NewRequestWithContext(ctx, method, fci.url, requestBody)
	if err != nil {
		slog.Error("doRequest failed to create request", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", method, "err", err)

		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if data != nil {
		request.Header.Add("Content-Type", applicationJSON)
	}
	request.Header.Add("Accept", applicationJSON)

	slog.Debug("doRequest", common.CtxIDLabel, ctx.Value(common.CtxID),
		"request.URL", request.URL, "data", string(data))

	response, err := fci.httpClient.Do(request)
	if err != nil {
		slog.Error("doRequest Do returned error", common.CtxIDLabel, ctx.Value(common.CtxID),
			"request", request, "err", err)
		dumpRequestAndResponse(ctx, request, data, nil, nil)

		return nil, fmt.Errorf("do returned error: %w", err)
	}

	return processResponse(ctx, request, data, response)
}

func processResponse(
	ctx context.Context,
	request *http.Request,
	requestData []byte,
	response *http.Response,
) (*OnDemandPodReply, error) {
	defer response.Body.Close()
	responseContent, err := io.ReadAll(response.Body)
	if err != nil {
		slog.Error("processResponse error while reading response body", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", request.Method, "err", err)
		dumpRequestAndResponse(ctx, request, requestData, response, nil)

		return nil, fmt.Errorf("error while reading response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		slog.Error("processResponse unexpected status code", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", request.Method, "status", response.StatusCode)
		dumpRequestAndResponse(ctx, request, requestData, response, responseContent)

		return nil, fmt.Errorf("%w: %d", errUnexpectedStatusCode, response.StatusCode)
	}

	slog.Debug("processResponse", common.CtxIDLabel, ctx.Value(common.CtxID), "response.Header", response.Header)

	odpReply := OnDemandPodReply{}
	slog.Debug("processResponse", common.CtxIDLabel, ctx.Value(common.CtxID), "responseContent", string(responseContent))
	contentType := response.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, applicationJSON) {
		err = json.NewDecoder(bytes.NewReader(responseContent)).Decode(&odpReply)
		if err != nil {
			slog.Error("processResponse decode response body failed", common.CtxIDLabel, ctx.Value(common.CtxID),
				"method", request.Method, "err", err)
			dumpRequestAndResponse(ctx, request, requestData, response, responseContent)

			return nil, fmt.Errorf("decode response body failed: %w", err)
		}
	} else {
		slog.Error("processResponse unexpected Content-Type", common.CtxIDLabel, ctx.Value(common.CtxID),
			"method", request.Method, "content-type", contentType)
		dumpRequestAndResponse(ctx, request, requestData, response, responseContent)

		return nil, fmt.Errorf("%w: %s", errUnexpectedContentType, contentType)
	}

	return &odpReply, nil
}

func dumpRequestAndResponse(ctx context.Context,
	request *http.Request, requestData []byte,
	response *http.Response, responseData []byte,
) {
	if reqDump, dumpErr := httputil.DumpRequest(request, false); dumpErr == nil {
		slog.Error("dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
			"request", string(reqDump))
	} else {
		slog.Error("dumpRequestAndResponse failed to dump request", "dumpErr", dumpErr)
	}
	if requestData != nil {
		slog.Error("dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
			"requestData", string(requestData))
	}

	if response != nil {
		if respDump, dumpErr := httputil.DumpResponse(response, false); dumpErr == nil {
			slog.Error("dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
				"response", string(respDump))
		} else {
			slog.Error("dumpRequestAndResponse failed to dump response", "dumpErr", dumpErr)
		}
	}

	if responseData != nil {
		slog.Error("dumpRequestAndResponse", common.CtxIDLabel, ctx.Value(common.CtxID),
			"responseData", string(responseData))
	}
}
