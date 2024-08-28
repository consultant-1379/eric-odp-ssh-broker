package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"eric-odp-ssh-broker/internal/testcommon"
)

func doHealthCheck(t *testing.T, expectedStatusCode int) {
	request := httptest.NewRequest(http.MethodGet, "/health/liveness", strings.NewReader(""))
	responseRecorder := httptest.NewRecorder()
	readinessHealthCheck(responseRecorder, request)

	response := responseRecorder.Result()
	gotStatusCode := response.StatusCode
	response.Body.Close()
	if gotStatusCode != expectedStatusCode {
		t.Errorf("unexpected statusCode to GET expected=%d got=%d", expectedStatusCode, gotStatusCode)
	}
}

func TestReadinessHealthCheck(t *testing.T) {
	atomic.StoreInt32(&isReady, 0)

	doHealthCheck(t, http.StatusServiceUnavailable)

	atomic.StoreInt32(&isReady, 1)
	doHealthCheck(t, http.StatusOK)
}

func TestMain(t *testing.T) {
	// Getting conflict in Jenkins with port 8002 so move to another port
	os.Setenv("SSO_URL", "http://sso/")
	os.Setenv("HEALTH_CHECK_PORT", fmt.Sprintf("%d", testcommon.GetFreePort(t)))
	os.Setenv("METRICS_PORT", fmt.Sprintf("%d", testcommon.GetFreePort(t)))
	os.Setenv("SSH_PORTS", fmt.Sprintf("%d", testcommon.GetFreePort(t)))
	os.Setenv("SSH_APPLICATIONS", "testapp")
	os.Setenv("SSH_HOST_KEY_FILE", testcommon.GenerateHostKey(t))

	var mainRunning atomic.Bool
	go func() {
		mainRunning.Store(true)
		main()
		mainRunning.Store(false)
	}()

	t.Log("Waiting for main to set isReady")
	for i := 0; i <= 100 && atomic.LoadInt32(&isReady) == 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if atomic.LoadInt32(&isReady) == 0 {
		t.Error("Service not ready")
	}

	t.Log("Make sure we are fully started")
	time.Sleep(time.Second)

	t.Log("Sending SIGTERM")
	exitSignal <- syscall.SIGTERM

	t.Log("Waiting for mainRunning to become false")
	for i := 0; i <= 100 && mainRunning.Load(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if mainRunning.Load() {
		t.Error("Main still running")
	}
}
