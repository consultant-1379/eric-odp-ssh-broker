package sshbroker

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"eric-odp-ssh-broker/internal/common"
	"eric-odp-ssh-broker/internal/config"
	"eric-odp-ssh-broker/internal/factory"
	"eric-odp-ssh-broker/internal/userauthn"
)

type BrokerConnection struct {
	externalConnection *ssh.ServerConn
}

type SshBrokerImpl struct { //nolint:revive,stylecheck // Easier to read CamelCase
	applications []string
	ports        []int

	tokenTypes         []string
	tokenDataPasswd    string
	tokenDataPasswdB64 bool // Temporary workaround for problem with token service
	odpSshPort         int  //nolint:revive,stylecheck // Easier to read CamelCase

	factoryClient factory.Interface
	userAuthn     userauthn.Interface

	ctx context.Context

	sshConfig *ssh.ServerConfig
	listeners []net.Listener

	maxConnections      int
	openConnections     atomic.Int32
	channelOpenTimeout  time.Duration
	channelCloseTimeout time.Duration

	odpConnectionAttempts int
	odpConnectionInterval time.Duration

	// connections is used when shutting down to
	// close all open connections. Need to do this
	// in particular for unit tests.
	connections      map[string]BrokerConnection
	connectionsMutex sync.RWMutex

	stopping atomic.Bool
	acceptWg sync.WaitGroup

	connectionsWg sync.WaitGroup
}

type Interface interface {
	Stop()
}

var (
	errTokenDataPasswordMissing = errors.New("could not get odp password from token data")
	errPasswordRejected         = errors.New("password rejected")
)

func NewSshBroker( //nolint:revive,stylecheck // Easier to read CamelCase
	ctx context.Context,
	cfg *config.Config,
	userAuthn userauthn.Interface,
	factoryClient factory.Interface,
) (*SshBrokerImpl, error) {
	sshApplications := strings.Split(cfg.SshApplications, ",")
	sshPortStrs := strings.Split(cfg.SshPorts, ",")
	sshPorts := make([]int, 0, len(sshPortStrs))
	for _, sshPortStr := range sshPortStrs {
		sshPort, err := strconv.Atoi(sshPortStr)
		if err != nil {
			return nil, fmt.Errorf("NewSshBroker failed to parse port number %s: %w", sshPortStr, err)
		}
		sshPorts = append(sshPorts, sshPort)
	}
	slog.Debug("SshBrokerImpl.NewSshBroker apps", "sshApplications", sshApplications)
	slog.Debug("SshBrokerImpl.NewSshBroker ports", "cfg.SshPorts", cfg.SshPorts, "sshPorts", sshPorts)

	sshBroker := SshBrokerImpl{
		applications: sshApplications,
		ports:        sshPorts,

		tokenTypes:         strings.Split(cfg.SshTokenTypes, ","),
		tokenDataPasswd:    cfg.SshTokenDataPasswd,
		tokenDataPasswdB64: cfg.SshTokenDataPasswdB64,

		odpSshPort: cfg.SshOdpPort,

		maxConnections:      cfg.SshMaxConnections,
		channelOpenTimeout:  time.Duration(cfg.SshChannelOpenTimeout) * time.Second,
		channelCloseTimeout: time.Duration(cfg.SshChannelCloseTimeout) * time.Second,

		odpConnectionAttempts: cfg.SshOdpConnectAttempts,
		odpConnectionInterval: time.Duration(cfg.SshOdpConnectInterval) * time.Second,

		factoryClient: factoryClient,
		userAuthn:     userAuthn,

		ctx:              ctx,
		stopping:         atomic.Bool{},
		acceptWg:         sync.WaitGroup{},
		connections:      make(map[string]BrokerConnection),
		connectionsMutex: sync.RWMutex{},
		connectionsWg:    sync.WaitGroup{},
		openConnections:  atomic.Int32{},
	}

	sshBroker.sshConfig = &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: sshBroker.AuthenticatePassword,
	}

	// Configure SSH Host Key to use
	hostKeySigner, err := getHostKey(cfg.SshHostKeyFile)
	if err != nil {
		return nil, err
	}
	sshBroker.sshConfig.AddHostKey(hostKeySigner)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	sshBroker.listeners = make([]net.Listener, 0, len(sshBroker.ports))
	for _, port := range sshBroker.ports {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			slog.Error("SshBrokerImpl listen failed", "SshPort", port, "err", err)

			return nil, fmt.Errorf("failed to listen: %w", err)
		}
		sshBroker.listeners = append(sshBroker.listeners, listener)
		sshBroker.acceptWg.Add(1)
	}

	setupMetrics(&sshBroker)

	for index, _ := range sshBroker.listeners {
		slog.Debug("SshBrokerImpl starting listener", "index", index)
		go func(appIndex int) {
			sshBroker.accept(appIndex)
			sshBroker.acceptWg.Done()
		}(index)
	}
	slog.Info("SshBrokerImpl Started")

	return &sshBroker, nil
}

func (sb *SshBrokerImpl) Stop() {
	slog.Info("SshBrokerImpl.Stop entered")

	sb.stopping.Store(true)

	waitForListeners := true
	for _, listener := range sb.listeners {
		if err := listener.Close(); err != nil {
			slog.Error("SshBrokerImpl.Stop failed to close ssh listener", "err", err)
			waitForListeners = false
		}
	}
	if waitForListeners {
		sb.acceptWg.Wait()
	}

	sb.connectionsMutex.RLock()
	for brokerConnectionKey, brokerConnection := range sb.connections {
		slog.Debug("SshBrokerImpl.Stop requesting close", "brokerConnectionKey", brokerConnectionKey)
		brokerConnection.externalConnection.Close()
	}
	sb.connectionsMutex.RUnlock()

	slog.Info("SshBrokerImpl.Stop waiting for all connections to be closed")
	sb.connectionsWg.Wait()

	slog.Info("SshBrokerImpl.Stop returning")
}

func (sb *SshBrokerImpl) AuthenticatePassword(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	slog.Debug("SshBrokerImpl.AuthenticatePassword", "user", c.User())

	result := sb.userAuthn.Authenticate(sb.ctx, c.User(), string(pass))
	slog.Info("SshBrokerImpl.AuthenticatePassword", "User", c.User(), "Addr", c.RemoteAddr().String(), "result", result)
	if result {
		return nil, nil
	}

	return nil, fmt.Errorf("%w: %q", errPasswordRejected, c.User())
}

func (sb *SshBrokerImpl) accept(appIndex int) {
	slog.Debug("SshBrokerImpl.accept entered", "application", sb.applications[appIndex])
	defer slog.Debug("SshBrokerImpl.accept returned", "application", sb.applications[appIndex])

	for {
		conn, err := sb.listeners[appIndex].Accept()
		recordAccept()

		if err != nil {
			if sb.stopping.Load() {
				slog.Info("SshBrokerImpl.accept stopping")

				return
			}

			log.Fatal("failed to accept incoming connection: ", err)
		}

		connectionAllowed := true
		if sb.maxConnections > 0 && int(sb.openConnections.Load()) >= sb.maxConnections {
			connectionAllowed = false
		}

		if connectionAllowed {
			go sb.handleOneConnection(conn, sb.applications[appIndex])
		} else {
			slog.Warn("SshBrokerImpl.accept connection refused due to connection limit", "remote", conn.RemoteAddr())
			recordAcceptRefused("toomany")
			conn.Close()
		}
	}
}

func (sb *SshBrokerImpl) handleOneConnection(netconn net.Conn, application string) {
	sb.openConnections.Add(1)
	defer sb.openConnections.Add(-1)

	// Need to track open connections so that the tests can really wait until all connections are closed
	sb.connectionsWg.Add(1)
	defer sb.connectionsWg.Done()

	ctx := context.WithValue(sb.ctx, common.CtxID, fmt.Sprintf("%s-%s", application, netconn.RemoteAddr().String()))
	slog.Debug("SshBrokerImpl.handleOneConnection entered", common.CtxIDLabel, ctx.Value(common.CtxID))
	defer slog.Debug("SshBrokerImpl.handleOneConnection returning", common.CtxIDLabel, ctx.Value(common.CtxID))

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	sshconn, externalNewChannels, connReqs, err := ssh.NewServerConn(netconn, sb.sshConfig)
	if err != nil {
		slog.Warn("SshBrokerImpl.handleOneConnection handshake failed", common.CtxIDLabel, ctx.Value(common.CtxID),
			"err", err)
		netconn.Close()

		return
	}
	defer sshconn.Close()

	// Register this connection in the connections map
	// Use a defer to remove it from the connections map
	// once this function returns
	brokerConnectionKey := netconn.RemoteAddr().String()
	brokerConnection := BrokerConnection{externalConnection: sshconn}
	sb.connectionsMutex.Lock()
	sb.connections[brokerConnectionKey] = brokerConnection
	sb.connectionsMutex.Unlock()
	defer func() {
		sb.connectionsMutex.Lock()
		delete(sb.connections, brokerConnectionKey)
		sb.connectionsMutex.Unlock()
	}()

	odpReply, clientErr := sb.factoryClient.GetOdp(ctx, sshconn.User(), application, sb.tokenTypes)
	var sshClient *ssh.Client
	if clientErr == nil {
		sshClient, clientErr = sb.getClient(ctx, sshconn.User(), odpReply)
	}

	// If we have an open client, then make sure that we close it when we're done
	if sshClient != nil {
		defer sshClient.Close()
	}

	// If there's any problem get the ODP or opening the connection to the ODP, we can't
	// just close the connection. We have to wait for the first channel request,
	// we need this to send back the failure reason

	go sb.fowardGlobalRequests(ctx, connReqs, sshClient, sshconn)

	slog.Debug("SshBrokerImpl.handleOneConnection wait for first channel",
		common.CtxIDLabel, ctx.Value(common.CtxID))

	// Also: implement a timeout on this wait
	channelIndex := 0
	select {
	case newChannel := <-externalNewChannels:
		if newChannel == nil {
			slog.Warn("SshBrokerImpl.handleOneConnection failed to get first channel",
				common.CtxIDLabel, ctx.Value(common.CtxID))

			return
		} else if clientErr != nil {
			slog.Warn("SshBrokerImpl.handleOneConnection rejecting channel",
				common.CtxIDLabel, ctx.Value(common.CtxID), "clientErr", clientErr)
			newChannel.Reject(ssh.Prohibited, clientErr.Error()) //nolint:errcheck // Don't care about result

			return
		} else {
			go sb.handleOneChannel(ctx, sshClient, newChannel, channelIndex)
		}
	case <-time.After(sb.channelOpenTimeout):
		slog.Warn("SshBrokerImpl.handleOneConnection timed out waiting for first channel",
			common.CtxIDLabel, ctx.Value(common.CtxID))

		return
	}

	slog.Info("SshBrokerImpl.handleOneConnection connected", common.CtxIDLabel, ctx.Value(common.CtxID),
		"User", sshconn.User(), "Addr", sshconn.RemoteAddr().String())

	// Service the any other incoming channel requests.
	for newChannel := range externalNewChannels {
		channelIndex++
		go sb.handleOneChannel(ctx, sshClient, newChannel, channelIndex)
	}

	slog.Info("SshBrokerImpl.handleOneConnection connection closing", common.CtxIDLabel, ctx.Value(common.CtxID),
		"User", sshconn.User(), "Addr", sshconn.RemoteAddr().String())
}

func (sb *SshBrokerImpl) fowardGlobalRequests(
	ctx context.Context,
	connReqs <-chan *ssh.Request,
	sshClient *ssh.Client,
	sshconn *ssh.ServerConn,
) {
	slog.Debug("SshBrokerImpl.fowardGlobalRequests starting",
		common.CtxIDLabel, ctx.Value(common.CtxID))

	for connReq := range connReqs {
		slog.Debug("SshBrokerImpl.fowardGlobalRequests Connection request",
			common.CtxIDLabel, ctx.Value(common.CtxID), "connReq", connReq)
		if sshClient != nil {
			result, payload, err := sshClient.SendRequest(connReq.Type, connReq.WantReply, connReq.Payload)
			if err != nil {
				slog.Warn("SshBrokerImpl.fowardGlobalRequests failed to send connection request to client",
					common.CtxIDLabel, ctx.Value(common.CtxID), "err", err, "connReq", connReq)
				sshClient.Close()
				sshconn.Close()
			}

			connReq.Reply(result, payload) //nolint:errcheck // Don't care about result
		} else {
			connReq.Reply(false, nil) //nolint:errcheck // Don't care about result
		}
	}

	slog.Debug("SshBrokerImpl.fowardGlobalRequests stopping",
		common.CtxIDLabel, ctx.Value(common.CtxID))
}

func (sb *SshBrokerImpl) getClient(
	ctx context.Context,
	username string,
	odpReply *factory.OnDemandPodReply,
) (*ssh.Client, error) {
	odpPassword, odpPasswordExists := odpReply.TokenData[sb.tokenDataPasswd]
	if !odpPasswordExists {
		slog.Error("SshBrokerImpl.getClient: Could not get token password", common.CtxIDLabel, ctx.Value(common.CtxID),
			"tokenDataPasswd", sb.tokenDataPasswd, "odpReply", odpReply)

		return nil, errTokenDataPasswordMissing
	}

	// Temporary workaround for problem with token service. Should be removed when
	// token service starts returning the correct data.
	if sb.tokenDataPasswdB64 {
		decodedPassword, err := base64.StdEncoding.DecodeString(odpPassword)
		if err != nil {
			return nil, fmt.Errorf("SshBrokerImpl.getClient Failed to decode password: %w", err)
		}

		odpPassword = string(decodedPassword)
		slog.Warn("SshBrokerImpl.getClient: workaround base64 decoded", common.CtxIDLabel, ctx.Value(common.CtxID),
			"odpPassword", odpPassword)
	}

	//nolint:revive,stylecheck // Easier to read CamelCase
	odpSshEndPoint := fmt.Sprintf("%s:%d", odpReply.PodIPs[0], sb.odpSshPort)

	sshClientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(odpPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // Needs to be updated when token service ready
	}

	var err error
	for connectionAttempt := 1; connectionAttempt <= sb.odpConnectionAttempts; connectionAttempt++ {
		slog.Debug("SshBrokerImpl.getClient Dialing",
			common.CtxIDLabel, ctx.Value(common.CtxID),
			"connectionAttempt", connectionAttempt,
			"odpConnectionAttempts", sb.odpConnectionAttempts)
		var client *ssh.Client
		client, err = ssh.Dial("tcp", odpSshEndPoint, sshClientConfig)
		if err == nil {
			return client, nil
		} else if connectionAttempt < sb.odpConnectionAttempts {
			// We'll have another attempt
			slog.Warn("SshBrokerImpl.getClient: Could not get ssh client, will retry",
				common.CtxIDLabel, ctx.Value(common.CtxID),
				"odpReply", odpReply,
				"connectionAttempt", connectionAttempt,
				"odpConnectionAttempts", sb.odpConnectionAttempts,
				"err", err)
			time.Sleep(sb.odpConnectionInterval)
		}
	}

	slog.Error("SshBrokerImpl.getClient: Could not get ssh client", common.CtxIDLabel, ctx.Value(common.CtxID),
		"odpReply", odpReply, "err", err)

	return nil, fmt.Errorf("could not get ssh connection for ODP: %w", err)
}

func (sb *SshBrokerImpl) handleOneChannel(
	connCtx context.Context,
	sshClient *ssh.Client,
	newChannel ssh.NewChannel,
	channelIndex int,
) {
	recordChannelOpen(newChannel.ChannelType())
	ctx := context.WithValue(connCtx, common.CtxID, fmt.Sprintf("%s-%d", connCtx.Value(common.CtxID), channelIndex))
	odpChannel, odpRequestCh, odpErr := sshClient.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if odpErr != nil {
		slog.Warn("SshBrokerImpl.handleOneChannel couldn't open client channel",
			common.CtxIDLabel, ctx.Value(common.CtxID),
			"channelType", newChannel.ChannelType(), "err", odpErr)
		newChannel.Reject(ssh.Prohibited, odpErr.Error()) //nolint:errcheck // Don't care about result

		return
	}
	defer odpChannel.Close()

	externalChannel, externalRequestCh, err := newChannel.Accept()
	if err != nil {
		slog.Warn("SshBrokerImpl.handleOneChannel not accept channel", common.CtxIDLabel, ctx.Value(common.CtxID),
			"err", err)
		odpChannel.Close()

		return
	}
	defer externalChannel.Close()

	copier := func(in, out ssh.Channel, istx bool) {
		slog.Debug("SshBrokerImpl.handleOneChannel Copier started", common.CtxIDLabel, ctx.Value(common.CtxID),
			"istx", istx)
		defer out.CloseWrite() //nolint:errcheck // Don't care about result

		src := InstrumentedReader{Reader: in, istx: istx}
		written, err := io.Copy(out, &src)
		slog.Debug("SshBrokerImpl.handleOneChannel Copier ended", common.CtxIDLabel, ctx.Value(common.CtxID),
			"istx", istx, "written", written, "err", err)
	}

	wg := sync.WaitGroup{}

	// Copy data from the ssh service on the ODP to the external client
	wg.Add(1)
	go func() {
		copier(odpChannel, externalChannel, true)
		wg.Done()
	}()

	// Copy data from the external client to the ssh service on the ODP
	wg.Add(1)
	go func() {
		copier(externalChannel, odpChannel, false)
		wg.Done()
	}()

	sb.forwardChannelRequests(ctx, externalChannel, externalRequestCh, odpChannel, odpRequestCh)

	// When forwardChannelRequests returns, one side the the channel must have closed.
	// Wait wait a timeout for both channels to be close. If they don't close cleanly
	// then force the channels closed
	slog.Debug("SshBrokerImpl.handleOneChannel waiting for copiers to exit",
		common.CtxIDLabel, ctx.Value(common.CtxID), "channelCloseTimeout", sb.channelCloseTimeout)
	closedCh := make(chan struct{})
	go func() {
		defer close(closedCh)
		wg.Wait()
	}()
	select {
	case <-closedCh:
		slog.Debug("SshBrokerImpl.handleOneChannel channels closed",
			common.CtxIDLabel, ctx.Value(common.CtxID))
	case <-time.After(sb.channelCloseTimeout):
		slog.Warn("SshBrokerImpl.handleOneChannel forcing channels close",
			common.CtxIDLabel, ctx.Value(common.CtxID))
		odpChannel.Close()
		externalChannel.Close()
		wg.Wait()
	}
	slog.Debug("SshBrokerImpl.handleOneChannel Done", common.CtxIDLabel, ctx.Value(common.CtxID))
}

// Forward Requests back and forth between the external client and the ssh service in the ODP.
func (sb *SshBrokerImpl) forwardChannelRequests(
	ctx context.Context,
	externalChannel ssh.Channel,
	externalRequestCh <-chan *ssh.Request,
	odpChannel ssh.Channel,
	odpRequestCh <-chan *ssh.Request,
) {
	slog.Debug("SshBrokerImpl.forwardChannelRequests entered", common.CtxIDLabel, ctx.Value(common.CtxID))
	defer slog.Debug("SshBrokerImpl.forwardChannelRequests returning", common.CtxIDLabel, ctx.Value(common.CtxID))

	for {
		select {
		case odpRequest := <-odpRequestCh:
			slog.Debug("SshBrokerImpl.forwardChannelRequests request from ODP",
				common.CtxIDLabel, ctx.Value(common.CtxID), "request", odpRequest)
			if odpRequest == nil {
				return
			}
			result, reqErr := externalChannel.SendRequest(odpRequest.Type, odpRequest.WantReply, odpRequest.Payload)
			slog.Debug("SshBrokerImpl.forwardChannelRequests reply from ODP", common.CtxIDLabel, ctx.Value(common.CtxID),
				"result", result, "reqErr", reqErr)
			odpRequest.Reply(result, nil) //nolint:errcheck // Don't care about result

		case externalRequest := <-externalRequestCh:
			slog.Debug("SshBrokerImpl.forwardChannelRequests request from external", common.CtxIDLabel, ctx.Value(common.CtxID),
				"request", externalRequest)
			if externalRequest == nil {
				return
			}
			result, reqErr := odpChannel.SendRequest(externalRequest.Type, externalRequest.WantReply, externalRequest.Payload)
			slog.Debug("SshBrokerImpl.forwardChannelRequests reply from external", common.CtxIDLabel, ctx.Value(common.CtxID),
				"result", result, "reqErr", reqErr)
			externalRequest.Reply(result, nil) //nolint:errcheck // Don't care about result
		}
	}
}

type InstrumentedReader struct {
	io.Reader
	istx bool
}

func (ir *InstrumentedReader) Read(p []byte) (int, error) {
	n, err := ir.Reader.Read(p)

	if n > 0 {
		recordTraffic(n, ir.istx)
	}

	return n, err //nolint:wrapcheck // Just wrapping interface here so don't wrap error
}
