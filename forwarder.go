package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type forwarder struct {
	Gate   gate
	ConnID string

	Principals string
	RemoteUser string

	agentForwarding     bool
	chanAgentForwarding chan bool

	localAddr  string
	remoteDest string // remote server where to forward connection

	// channel to send the listen port
	chanListenPort chan int

	// channel used to copy requests from client to remote server
	maskedReqs chan *ssh.Request

	// client connection
	InitialClientSshCon *ssh.ServerConn
	clientSshConn       *ssh.ServerConn

	// client channel & requests
	clientChannel     *LogChannel
	clientRawChannel  ssh.Channel
	clientRequests    <-chan *ssh.Request
	clientNewChannel  <-chan ssh.NewChannel
	clientNewRequests <-chan *ssh.Request

	// remote connection (to remote server)
	remoteSshConn *ssh.Client
	// remote channel & requests (remote server)
	remoteChannel  ssh.Channel
	remoteRequests <-chan *ssh.Request
}

func (f *forwarder) Forward() {
	log1(fmt.Sprintf("%s Entering Forwarder. Destination -> %s", f.ConnID, f.remoteDest))

	// basic SSH server config
	sshdConfig := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-" + f.Gate.Config.Forwarder.ServerName,
	}

	// load host key (same as proxy)
	sshdConfig.AddHostKey(loadHostKeys(f.Gate.Config.Hostkey))

	// Setup SSH Banner
	sshdConfig.BannerCallback = func(conn ssh.ConnMetadata) string {
		return banner(f.Gate.Config.Forwarder.Banner)
	}

	// TODO : ciphers
	sshdConfig.Config.Ciphers = []string{"aes256-ctr"}
	sshdConfig.Config.MACs = []string{"hmac-sha1"}
	sshdConfig.Config.KeyExchanges = []string{"ecdh-sha2-nistp384"}

	// open a socket to listen on SSH port
	debug(fmt.Sprintf("%s Open the next available socket ...", f.ConnID))
	listener, err := net.Listen("tcp4", ":0")
	if err != nil {
		log.Fatalf("failed to listen on *:0")
	}

	// get the listen port and send back to the tcpip proxy
	f.chanListenPort <- listener.Addr().(*net.TCPAddr).Port

	// Accept the next connection - Only one time
	log1(fmt.Sprintf("%s Listen on *:%d ...", f.ConnID, listener.Addr().(*net.TCPAddr).Port))
	tcpConn, err := listener.Accept()
	if err != nil {
		debug(fmt.Sprintf("%s Failed to accept incoming connection (%s)\n", f.ConnID, err))
		return
	}

	// close the listen socket, we don't need it anymore
	// It's good for security reason, even if it's only listen to localhost
	listener.Close()

	// This channel will be used to copy request from the client to the server
	// It's not mandatory for the moment but will permit in the future to do action
	// depending the request type
	f.maskedReqs = make(chan *ssh.Request, 5)

	// NewServerConn starts a new SSH server with c as the underlying transport.
	// It starts with a handshake and, if the handshake
	// is unsuccessful, it closes the connection and returns an error. The Request
	// and NewChannel channels must be serviced, or the connection will hang.
	// This server will receive the initial connection from "proxy"
	f.clientSshConn, f.clientNewChannel, f.clientNewRequests, err = ssh.NewServerConn(tcpConn, sshdConfig)
	if err != nil {
		debug(fmt.Sprintf("%s Failed to handshake (%s)", f.ConnID, err))
		return
	}
	log1(fmt.Sprintf("%s Connection accepted from %s (%s) (from proxy)", f.ConnID, f.clientSshConn.RemoteAddr(), f.clientSshConn.ClientVersion()))

	// Get remote user for the destination connection
	f.RemoteUser = f.getRemoteUser()
	if f.RemoteUser == "" { // if empty, no need to continue
		return // will close the connection
	}

	// Print incoming out-of-band Requests
	go f.handleRequests()

	// Accept all channels
	go f.handleChannels()
}

// Print incoming out-of-band Requests
func (f *forwarder) handleRequests() {
	for req := range f.clientNewRequests {
		debug(fmt.Sprintf("%s recieved out-of-band request: %+v", f.ConnID, req))
	}
}

// handle channel requests
// only accept session type
func (f *forwarder) handleChannels() {

	var err error

	// Service the incoming Channel channel.
	for newChannel := range f.clientNewChannel {

		// Channels of type "session" handle requests that are involved in running
		// commands on a server, subsystem requests, and agent forwarding.
		if t := newChannel.ChannelType(); t != "session" {
			debug(fmt.Sprintf("%s Channel type rejected (only session) %s", f.ConnID, t))
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("Channel type rejected (only session) %s", t))
			continue
		}

		// Accept accepts the channel creation request. It returns the Channel
		// and a Go channel containing SSH requests. The Go channel must be
		// serviced otherwise the Channel will hang.
		f.clientRawChannel, f.clientRequests, err = newChannel.Accept()
		if err != nil {
			debug(fmt.Sprintf("%s Could not accept channel: %s", f.ConnID, err))
			continue
		}

		// Log
		startTime := time.Now()
		f.clientChannel = NewLogChannel(startTime, f.clientRawChannel, f.RemoteUser, f.remoteDest, f.Gate.Config.Log.LogDir)

		// channel to synchronise Requests for AgentForwarding
		f.chanAgentForwarding = make(chan bool, 1)

		// handle all requests in a routine
		go f.handleSessionRequests()

		// Connect to the destination
		f.remoteConnection()
	}
}

// handle session requests
// Channels of type "session" handle requests that are involved in running
// commands on a server, subsystem requests, and agent forwarding.
func (f *forwarder) handleSessionRequests() {

	debug(fmt.Sprintf("%s Handle Session RemoteAddr Final: %s", f.ConnID, f.remoteDest))
	for req := range f.clientRequests {

		// Log
		f.clientChannel.LogRequest(req)

		// The client has closed or dropped the connection.
		if req == nil {
			debug(fmt.Sprintf("%s Client has closed or dropped the connection: %s", f.ConnID, f.clientSshConn.RemoteAddr()))
			return
		}

		switch req.Type {

		// forward SSH Agent
		// We have to synchronise this goroutine with the function remoteConenction()
		// which need AgentForwarding be at true
		case "auth-agent-req@openssh.com":
			if req.WantReply {
				req.Reply(true, []byte{})
			}
			f.maskedReqs <- req
			f.agentForwarding = true
			f.chanAgentForwarding <- true
			debug(fmt.Sprintf("%s Agent forwarding enabled", f.ConnID))

		case "pty-req":
			if req.WantReply {
				req.Reply(true, []byte{})
			}
			req.WantReply = false

			// disabled pty-req forwarding to avoid the closing of the connection
			// on remote host because we already request a terminal at connection
			//f.maskedReqs <- req

		case "shell":
			if req.WantReply {
				req.Reply(true, []byte{})
			}
			req.WantReply = false
			f.maskedReqs <- req

		default:
			f.maskedReqs <- req
		}

		// For the moment, copy request without change
		if req.WantReply {
			req.Reply(true, []byte{})
		}
		req.WantReply = false
		f.maskedReqs <- req
	}
}

// remoteConnection make a connection to the destination
// destination is provided by the original client with -W "%h:%p"
func (f *forwarder) remoteConnection() {

	var err error

	// retreive destination from session request
	// will wait until the data come in the channel
	debug(fmt.Sprintf("%s Forwarder is preparing to connect to the destination", f.ConnID))
	remoteAddr := f.remoteDest // TODO : add a timeout

	// Currently we only support auth through SSH Agent forward
	clientConfig := &ssh.ClientConfig{
		User: f.RemoteUser,

		// TODO : add a method to handle hostkey validation
		// at least record the hostkey the first time to avoid future MITM attack
		// It could be cool to have a central service to store the keys to share it accross a "cluster"
		// of proxy. May be consul with K/V ? Or a simple Redis ? (consul HA will be easier to deploy)
		// Add an option to to host key signature validation (deploy signed host key on target)
		// Add an option (API/CLI to update/purge entries)
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	debug(fmt.Sprintf("%s Remote user: %s", f.ConnID, f.RemoteUser))

	// Setup SSH crypto
	if len(f.Gate.Config.Forwarder.Ciphers) > 0 {
		clientConfig.Config.Ciphers = f.Gate.Config.Forwarder.Ciphers
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this ciphers: %s", clientConfig.Config.Ciphers))
		}
	}
	if len(f.Gate.Config.Forwarder.Macs) > 0 {
		clientConfig.Config.MACs = f.Gate.Config.Forwarder.Macs
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this macs: %s", clientConfig.Config.MACs))
		}
	}
	if len(f.Gate.Config.Forwarder.KeyExchange) > 0 {
		clientConfig.Config.KeyExchanges = f.Gate.Config.Forwarder.KeyExchange
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this keyExchange: %s", clientConfig.Config.KeyExchanges))
		}
	}

	// Agent Forwarding
	select {
	case _ = <-f.chanAgentForwarding:
		agentChan, agentReqs, err := f.InitialClientSshCon.OpenChannel("auth-agent@openssh.com", nil)
		if err == nil {
			defer agentChan.Close()
			go ssh.DiscardRequests(agentReqs)

			// Set up the client
			ag := agent.NewClient(agentChan)

			// Make sure PK is first in the list if supported.
			clientConfig.Auth = append([]ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}, clientConfig.Auth...)
		} else {
			debug(fmt.Sprintf("=======> %s", err))
			fmt.Fprintf(f.clientChannel, "AgentForwarding have to be enable ! Closing connection. (%s)\r\n", remoteAddr, err)
			f.clientSshConn.Close()
		}
	case <-time.After(2 * time.Second):
		log1("Unable to get agent forwarding request after 2 seconds ... abord connection")
		fmt.Fprintf(f.clientChannel, "AgentForwarding have to be enable ! Closing connection.\r\n")
		f.clientSshConn.Close()
	}

	debug(fmt.Sprintf("%s Connecting to remote desination ... %s", f.ConnID, remoteAddr))
	f.remoteSshConn, err = ssh.Dial("tcp", remoteAddr, clientConfig)
	if err != nil {
		debug(fmt.Sprintf("%s Connection failed to remote host %s : %s", f.ConnID, remoteAddr, err))
		fmt.Fprintf(f.clientChannel, "Connection failed to remote host: %s \r\n\t => %s\r\n", remoteAddr, err)
		f.clientSshConn.Close()
		return
	}
	defer f.remoteSshConn.Close()
	debug(fmt.Sprintf("%s Dialled remote destination successfully ...", f.ConnID))

	// Forward the session channel
	f.remoteChannel, f.remoteRequests, err = f.remoteSshConn.OpenChannel("session", []byte{})
	if err != nil {
		debug(fmt.Sprintf("%s Remote session setup failed: %v", f.ConnID, err))
		fmt.Fprintf(f.clientChannel, "Remote session setup failed: %v\r\n", err)
		f.clientSshConn.Close()
		return
	}

	err = f.clientChannel.SyncToFile("remote_name")
	if err != nil {
		debug(fmt.Sprintf("%s Failed to Initialize Session", f.ConnID))
		fmt.Fprintf(f.clientChannel, "Failed to Initialize Session.\r\n")
		f.clientChannel.Close()
		return
	}

	fmt.Fprintf(f.clientChannel, "Connection to remote host established. Enjoy !\r\n\n")

	// launch proxy service
	f.proxy()
}

func (f *forwarder) proxy() {

	debug(fmt.Sprintf("%s Entering mode proxy ...", f.ConnID))

	// close channels and connections
	var closer sync.Once
	closeFunc := func() {
		f.clientChannel.Close()
		f.remoteChannel.Close()
		f.clientSshConn.Close()
		f.remoteSshConn.Close()
	}

	defer closer.Do(closeFunc)
	closerChan := make(chan bool, 1)

	// From remote, to client.
	go func() {
		io.Copy(f.clientChannel, f.remoteChannel)
		closerChan <- true // handle end of connection
	}()

	// from client to remote
	go func() {
		io.Copy(f.remoteChannel, f.clientChannel)
		closerChan <- true // handle end of connection
	}()

	for {
		select {

		// send from client to remote
		case req := <-f.maskedReqs:
			if req == nil {
				return
			}
			b, err := f.remoteChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)

		// send from remote to client
		case req := <-f.remoteRequests:
			if req == nil {
				return
			}
			b, err := f.clientChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}

// getRemoteUser return user to connect to destination
// based on configuration
func (f *forwarder) getRemoteUser() string {
	// return remote user by order or priority
	if f.Gate.Config.Forwarder.RemoteUserPrincipal {
		debug(fmt.Sprintf("%s Get remote username from principals ...", f.ConnID))
		return f.getPrincipal(remoteRealm, f.Principals)
	}
	if p := f.Gate.Config.Forwarder.RemoteUser; p != "" {
		debug(fmt.Sprintf("%s Get remote username from configuration ...", f.ConnID))
		return p
	}
	debug(fmt.Sprintf("%s Get remote username from client ...", f.ConnID))
	return f.clientSshConn.User()
}

// getPrincipal
func (f *forwarder) getPrincipal(principal string, principals string) string {
	p := strings.Split(principals, ",")
	for i := 0; i < len(p); i++ {
		c := strings.Split(p[i], ":")
		if c[0] == principal {
			debug(fmt.Sprintf("%s Find \"%s\" from principals \"%s\"", f.ConnID, principal, principals))
			return c[1]
		}
	}
	log1(fmt.Sprintf("%s Unable to \"%s\" in principals %s", f.ConnID, principal, principals))
	return ""
}
