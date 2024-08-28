package sshbroker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/factory"
	"eric-odp-ssh-broker/internal/testcommon"

	"golang.org/x/crypto/ssh"
)

type exitStatusMsg struct {
	Status uint32
}

type TestOdpSshSrv struct { //nolint:revive,stylecheck // Easier to read CamelCase
	config   *ssh.ServerConfig
	listener net.Listener
	t        *testing.T
	authWg   *sync.WaitGroup

	connectionOpen atomic.Bool
}

type TestFactory struct {
	replies []TestFactoryReply
	index   int
}

type TestFactoryReply struct {
	reply *factory.OnDemandPodReply
	err   error
}

func (tf *TestFactory) GetOdp(
	_ context.Context,
	_, _ string,
	_ []string,
) (*factory.OnDemandPodReply, error) {
	resultIndex := tf.index
	tf.index++

	return tf.replies[resultIndex].reply, tf.replies[resultIndex].err
}

type TestUserAuthn struct {
	username string
	password string
	t        *testing.T
}

func (tan *TestUserAuthn) Authenticate(_ context.Context, username, password string) bool {
	result := tan.username == username && tan.password == password
	slog.Info("TestUserAuthn.Authenticate", "result", result, "username", username, "password", password)

	return result
}

var testCtx = context.WithValue(context.TODO(), common.CtxID, "test")

func TestMain(m *testing.M) {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	os.Exit(m.Run())
}

func TestSshConnectOkay(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))
	go tossh.Run()
	defer tossh.listener.Close()

	client := connectClient(t, sshListenPort)

	if requestReply, _, err := client.SendRequest("unknown-request", true, nil); err != nil {
		t.Errorf("unexpected error when sending global requuest: %v", err)
	} else if requestReply {
		t.Error("expected requestReply to be false")
	}

	// We run a number of iterations to make sure there aren't
	// any race condition problems and that we handle multiple
	// channels on the same connection.
	for index := 0; index < 100; index++ {
		verifyExecClose(t, client, "", false)
	}

	client.Close()

	sshBroker.Stop()
}

// Verify that the connection to the ODP is closed when
// we close the client connection to the broker.
func TestSshClientClosed(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))
	go tossh.Run()
	defer tossh.listener.Close()

	client := connectClient(t, sshListenPort)

	if _, err := client.NewSession(); err != nil {
		t.Fatalf("Expected to get a session")
	}

	// Now close the client and make sure that
	// the connection to the ODP SSH is closed by
	// the broker.
	client.Close()

	for iteration := 0; iteration < 10 && tossh.connectionOpen.Load(); iteration++ {
		time.Sleep(time.Millisecond * time.Duration(100))
	}
	if tossh.connectionOpen.Load() {
		t.Errorf("Connection is still open")
	}

	sshBroker.Stop()
}

func TestSshConnectionWithRetry(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	sshBroker.odpConnectionAttempts = 2
	sshBroker.odpConnectionInterval = time.Millisecond

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))

	// Force the first connection attempt to fail and the next will pass.
	// This should trigger a retry in getClient
	callCount := 0
	tossh.config.PasswordCallback = func(c ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
		callCount++
		slog.Debug("TestSshConnectionWithRetry.PasswordCallback", "callCount", callCount)
		if callCount < 2 {
			return nil, fmt.Errorf("password rejected for %q", c.User()) //nolint:err113 // Ignore for test
		}

		return nil, nil
	}

	go tossh.Run()
	defer tossh.listener.Close()

	client := connectClient(t, sshListenPort)
	if client == nil {
		t.Fatalf("expected to get a client")
	}
	defer client.Close()

	if _, err := client.NewSession(); err != nil {
		t.Fatalf("Expected to get a session")
	}

	if callCount != 2 {
		t.Fatalf("Expected callCount to be 2 due to retry")
	}

	sshBroker.Stop()
}

func TestSshSelfHostKey(t *testing.T) {
	// Verify we still get a broker when we don't
	// provide external host key
	_, _, sshBroker, _, _ := setupWithOpt(t, false) //nolint:dogsled // Ignore for testing
	sshBroker.Stop()
}

func TestSshConnectFailAuth(t *testing.T) {
	userAuthn, _, sshBroker, sshListenPort, _ := setup(t)
	userAuthn.password = "differentpassword"

	client, err := dialClient(sshListenPort)
	if err == nil {
		t.Fatalf("expected failure to get ssh client: %v", client)
	}

	sshBroker.Stop()
}

func TestSshConnectOdpError(t *testing.T) {
	_, factoryClient, sshBroker, sshListenPort, _ := setup(t)

	factoryClient.replies[0].err = errors.New("Some ODP error") //nolint:err113 // Ignore for test
	factoryClient.replies[0].reply = nil

	client := connectClient(t, sshListenPort)

	verifyExec(t, client, "ssh: rejected: administratively prohibited (Some ODP error)")
	sshBroker.Stop()
}

func TestSshConnectOdpMissingPassword(t *testing.T) {
	_, factoryClient, sshBroker, sshListenPort, _ := setup(t)

	// Remove the password field from the TokenData
	delete(factoryClient.replies[0].reply.TokenData, "sso")

	client := connectClient(t, sshListenPort)

	verifyExec(t, client, "ssh: rejected: administratively prohibited (could not get odp password from token data)")
	sshBroker.Stop()
}

func TestSshConnectOdpCannotConnect(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpPort := setup(t)

	// Don't setup ODP ssh service so should fail to connection
	client := connectClient(t, sshListenPort)

	//nolint:lll // It's just a print
	expectedError := fmt.Sprintf("ssh: rejected: administratively prohibited (could not get ssh connection for ODP: dial tcp 127.0.0.1:%d: connect: connection refused)", odpPort)
	verifyExec(t, client, expectedError)
	sshBroker.Stop()
}

func TestSshConnectOdpChannelReject(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))
	go tossh.Run()
	defer tossh.listener.Close()

	// Don't setup ODP ssh service so should fail to connection
	client := connectClient(t, sshListenPort)

	if _, _, err := client.OpenChannel("badtype", nil); err == nil {
		t.Errorf("expected err when opening unsupported channel type")
	}

	sshBroker.Stop()
	client.Close()
}

func TestSshConnectTooMany(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))
	go tossh.Run()
	defer tossh.listener.Close()

	client1 := connectClient(t, sshListenPort)
	client2, err := dialClient(sshListenPort)
	if err == nil {
		t.Fatal("expected client 2 to fail due to maxConnections")
	}

	if err := client1.Close(); err != nil {
		t.Errorf("Failed to close client1: %v", err)
	}
	if client2 != nil {
		t.Logf("Closing client2")
		if err := client2.Close(); err != nil {
			t.Errorf("Failed to close client1: %v", err)
		}
	}

	sshBroker.Stop()
}

func TestMissingSshKey(t *testing.T) {
	keyDir := t.TempDir()
	cfg := config.Config{SshHostKeyFile: keyDir + "/id_rsa"}
	_, err := NewSshBroker(testCtx, &cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error with missing host key file")
	}
}

func TestBadSshKey(t *testing.T) {
	keyDir := t.TempDir()
	cfg := config.Config{SshHostKeyFile: keyDir + "/id_rsa"}
	os.WriteFile(cfg.SshHostKeyFile, []byte("badkey\n"), 0o600)

	_, err := NewSshBroker(testCtx, &cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error with bad host key file")
	}
}

func TestFailListen(t *testing.T) {
	sshListenPort := testcommon.GetFreePort(t)
	t.Logf("TestFailListen sshListenPort=%d", sshListenPort)

	cfg := config.Config{
		SshHostKeyFile:  testcommon.GenerateHostKey(t),
		SshPorts:        fmt.Sprintf("%d", sshListenPort),
		SshApplications: "app",
	}

	listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", sshListenPort))
	defer listener.Close()

	_, err := NewSshBroker(testCtx, &cfg, nil, nil)
	if err == nil {
		t.Fatal("expected error due to listen failure")
	}
}

func TestSshConnectSessionTimeout(t *testing.T) {
	_, _, sshBroker, sshListenPort, odpListenPort := setup(t)

	tossh := getOdpSshSrv(t, odpListenPort, testcommon.GenerateHostKey(t))
	go tossh.Run()
	defer tossh.listener.Close()

	authWg := sync.WaitGroup{}
	authWg.Add(1)
	tossh.authWg = &authWg

	sshBroker.channelOpenTimeout = time.Microsecond

	client := connectClient(t, sshListenPort)

	// Wait for authenication to complete then sleep
	// for longer then the channelOpenTimeout.
	authWg.Wait()
	time.Sleep(100 * time.Millisecond)

	if _, err := client.NewSession(); err == nil {
		t.Fatalf("Expected to get an error due to session timeout")
	}

	client.Close()

	sshBroker.Stop()
}

func setupWithOpt(t *testing.T, externalHostKey bool) (*TestUserAuthn, *TestFactory, *SshBrokerImpl, int, int) {
	userAuthn := TestUserAuthn{username: "testuser", password: "testpassword", t: t}
	factoryClient := TestFactory{
		replies: []TestFactoryReply{
			{
				reply: &factory.OnDemandPodReply{
					TokenData: map[string]string{"sso": "ssotokendata"},
					PodIPs:    []string{"127.0.0.1"},
				},
				err: nil,
			},
		},
	}

	sshListenPort := testcommon.GetFreePort(t)
	odpListenPort := testcommon.GetFreePort(t)

	cfg := config.Config{
		SshPorts:               fmt.Sprintf("%d", sshListenPort),
		SshApplications:        "testapp",
		SshOdpPort:             odpListenPort,
		SshMaxConnections:      1,
		SshTokenDataPasswd:     "sso",
		SshTokenTypes:          "sso",
		SshChannelOpenTimeout:  10,
		SshChannelCloseTimeout: 1,
		SshOdpConnectAttempts:  1,
		SshOdpConnectInterval:  1,
	}

	if externalHostKey {
		cfg.SshHostKeyFile = testcommon.GenerateHostKey(t)
	}

	sshBroker, err := NewSshBroker(testCtx, &cfg, &userAuthn, &factoryClient)
	if err != nil {
		t.Fatalf("NewSshBroker returned unexpected error %v", err)
	}

	return &userAuthn, &factoryClient, sshBroker, sshListenPort, odpListenPort
}

func setup(t *testing.T) (*TestUserAuthn, *TestFactory, *SshBrokerImpl, int, int) {
	return setupWithOpt(t, true)
}

func dialClient(sshListenPort int) (*ssh.Client, error) {
	sshClientConfig := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpassword"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	//nolint:wrapcheck // Ignore for test
	return ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshListenPort), sshClientConfig)
}

func connectClient(t *testing.T, sshListenPort int) *ssh.Client {
	client, err := dialClient(sshListenPort)
	if err != nil {
		t.Fatalf("unexpected failure to get ssh client: %v", err)
	}

	return client
}

func verifyExec(t *testing.T, client *ssh.Client, expectFailure string) {
	verifyExecClose(t, client, expectFailure, true)
}

func verifyExecClose(t *testing.T, client *ssh.Client, expectFailure string, closeClient bool) {
	if closeClient {
		defer client.Close()
	}

	session, err := client.NewSession()
	slog.Info("broker_test.verifyExecClose session", "err", err)
	if expectFailure != "" {
		if err == nil {
			session.Close()
			t.Fatal("Expected session failure")
		} else if err.Error() != expectFailure {
			t.Fatalf("Expected different session failure, expected %s, got %s", expectFailure, err.Error())
		} else {
			return
		}
	} else {
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
	}

	defer session.Close()

	expectedReply := "testreply\n"
	var out []byte
	out, err = session.CombinedOutput("echo")
	if err != nil {
		t.Fatalf("Failed to run: %v", err)
	} else {
		slog.Info("broker_test.verifyExecClose result", "out", string(out))
		if string(out) != expectedReply {
			t.Fatalf("expected %s got %s", expectedReply, (out))
		}
	}
}

//nolint:revive,stylecheck // Easier to read CamelCase
func getOdpSshSrv(t *testing.T, port int, hostKeyFile string) *TestOdpSshSrv {
	odpSshSrv := TestOdpSshSrv{t: t} //nolint:revive,stylecheck // Easier to read CamelCase

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	odpSshSrv.config = &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if odpSshSrv.authWg != nil {
				odpSshSrv.authWg.Done()
			}

			slog.Info("odpSshSrv PasswordCallback called", "user", c.User(), "password", string(pass))
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == "testuser" && string(pass) == "ssotokendata" {
				return nil, nil
			}

			return nil, fmt.Errorf("password rejected for %q", c.User()) //nolint:err113 // Ignore for test
		},
	}

	privateBytes, err := os.ReadFile(hostKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
	odpSshSrv.config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	odpSshSrv.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to listen for connection: %v", err)
	}

	return &odpSshSrv
}

func (tossh *TestOdpSshSrv) Run() {
	for {
		c, err := tossh.listener.Accept()
		if err != nil {
			log.Printf("TestOdpSshSrv.Run failed to accept incoming connection: %v", err)

			return
		}

		tossh.connectionOpen.Store(true)
		handleSrvConnection(c, tossh.config)
		tossh.connectionOpen.Store(false)
	}
}

func handleSrvConnection(c net.Conn, sshServerConfig *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	serverConn, chans, reqs, err := ssh.NewServerConn(c, sshServerConfig)
	if err != nil {
		slog.Warn("TestOdpSshSrv.Run open server connection", "err", err)

		return
	}
	defer serverConn.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	// The incoming Request channel must be serviced.
	wg.Add(1)
	go func() {
		ssh.DiscardRequests(reqs)
		wg.Done()
	}()

	// Service the incoming Channel channel.
	for newChannel := range chans {
		slog.Info("TestOdpSshSrv.Run got new channel", "newChannel.ChannelType()", newChannel.ChannelType())
		go handleSrvChannel(newChannel)
	}
}

func handleSrvChannel(newChannel ssh.NewChannel) {
	// Channels have a type, depending on the application level
	// protocol intended. In the case of a shell, the type is
	// "session" and ServerShell may be used to present a simple
	// terminal interface.
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")

		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Could not accept channel: %v", err)
	}

	gotExecWg := sync.WaitGroup{}
	gotExecWg.Add(1)

	wgRequestHandlerDone := sync.WaitGroup{}
	wgRequestHandlerDone.Add(1)

	go func(in <-chan *ssh.Request) {
		for req := range in {
			ok := req.Type == "exec"
			slog.Info("TestOdpSshSrv.Run got new req", "req.Type", req.Type, "ok", ok)
			req.Reply(ok, nil)
			gotExecWg.Done()
		}
		slog.Info("TestOdpSshSrv.Run req loop done")
		wgRequestHandlerDone.Done()
	}(requests)

	gotExecWg.Wait()

	slog.Info("TestOdpSshSrv.Run sending reply")
	channel.Write([]byte("testreply\n"))
	channel.CloseWrite()
	channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: 0}))
	channel.Close()
}
