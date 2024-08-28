package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/dirwatcher"
	"eric-odp-ssh-broker/internal/factory"
	"eric-odp-ssh-broker/internal/sshbroker"
	"eric-odp-ssh-broker/internal/userauthn"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	idleTimeout  = 30 * time.Second
)

var (
	appConfig    *config.Config
	isReady      int32
	exitSignal   chan os.Signal
	healthHTTPD  *http.Server
	metricsHTTPD *http.Server
)

func readinessHealthCheck(w http.ResponseWriter, _ *http.Request) {
	if atomic.LoadInt32(&isReady) == 1 {
		_, _ = fmt.Fprintf(w, "OK")

		return
	}

	slog.Error("Service is not ready")

	w.WriteHeader(http.StatusServiceUnavailable)
}

func getExitSignalsChannel() chan os.Signal {
	channel := make(chan os.Signal, 1)
	signal.Notify(channel,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	return channel
}

func initHealthCheck() {
	addr := fmt.Sprintf(":%d", appConfig.HealthCheckPort)
	mux := http.NewServeMux()

	mux.HandleFunc("/health/liveness", readinessHealthCheck)
	mux.HandleFunc("/health/readiness", readinessHealthCheck)

	slog.Info("Adding /debug/ handler")
	mux.HandleFunc("/debug/", handleDebug)

	healthHTTPD = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	slog.Info("Starting healthcheck httpd service", "addr", addr)
	if err := healthHTTPD.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("healthcheck httpd service error %v", err)
	}

	slog.Info("healthcheck httpd service shutdown")
}

func initMetricsProvider() {
	addr := fmt.Sprintf(":%d", appConfig.MetricsPort)
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())

	metricsHTTPD = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	slog.Info("Starting metrics httpd service", "addr", addr)
	if err := metricsHTTPD.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("metrics httpd service error %v", err)
	}

	slog.Info("metrics httpd service shutdown")
}

func main() {
	if err := dirwatcher.Start(); err != nil {
		log.Fatalf("failed to start dirwatcher: %v", err)
	}

	appConfig = config.GetConfig()
	initLogging()

	slog.Info("Starting service", "appConfig", appConfig)

	ctx, cancel := context.WithCancel(context.Background())
	exitSignal = getExitSignalsChannel()

	atomic.StoreInt32(&isReady, 0)

	wg := sync.WaitGroup{}

	go initHealthCheck()
	go initMetricsProvider()

	userAuthn, err := userauthn.NewUserAuthn(appConfig)
	if err != nil {
		log.Fatal(err)
	}

	factoryClient := factory.NewFactoryClient(appConfig)

	sshBroker, err := sshbroker.NewSshBroker(ctx, appConfig, userAuthn, factoryClient)
	if err != nil {
		log.Fatalf("Failed to create sshBroker: %v", err)
	}

	atomic.StoreInt32(&isReady, 1)
	slog.Info("Startup completed")

	// Wait for exit signal
	<-exitSignal
	slog.Info("Received exit signal")

	// Shutdown
	cancel()

	healthHTTPD.Shutdown(context.Background())  //nolint:errcheck // We're shutting down so don't care about result
	metricsHTTPD.Shutdown(context.Background()) //nolint:errcheck // We're shutting down so don't care about result

	sshBroker.Stop()
	dirwatcher.Stop()

	slog.Info("Waiting for the services to terminate")
	wg.Wait()
	slog.Info("Terminated service")
}
