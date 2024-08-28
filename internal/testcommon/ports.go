package testcommon

import (
	"net"
	"testing"
)

func GetFreePort(t *testing.T) int {
	var port int

	var tcpAddr *net.TCPAddr
	var err error
	if tcpAddr, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var tcpListener *net.TCPListener
		if tcpListener, err = net.ListenTCP("tcp", tcpAddr); err == nil {
			port = tcpListener.Addr().(*net.TCPAddr).Port
			tcpListener.Close()
		} else {
			t.Fatalf("Failed to get listener: %v", err)
		}
	} else {
		t.Fatalf("Failed to resolve: %v", err)
	}

	return port
}
