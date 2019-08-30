package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// Mutex protecting 'authorisedKeys' map
	authmutex sync.Mutex
)

// Structure that holds all information for each connection/client
type sshClient struct {
	Name       string
	Principals string

	// We keep track of the normal Conn as well so that we have access to the
	// SetDeadline() methods
	Conn net.Conn

	SshConn *ssh.ServerConn

	// Listener sockets opened by the client
	Listeners map[string]net.Listener

	// This indicates that a client is shutting down. When a client is stopping,
	// we do not allow new listening requests, to prevent a listener connection
	// being opened just after we closed all of them.
	Stopping    bool
	ListenMutex sync.Mutex
}

// Structure containing what address/port we should bind on, for forwarded-tcpip
// connections
type bindInfo struct {
	Bound string
	Port  uint32
	Addr  string
}

// Information parsed from the authorized_keys file
type deviceInfo struct {
	LocalPorts  string
	RemotePorts string
	Comment     string
}

/* RFC4254 7.2 */
type directTCPPayload struct {
	Addr       string // To connect to
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type forwardedTCPPayload struct {
	Addr       string // Is connected to
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type tcpIpForwardPayload struct {
	Addr string
	Port uint32
}

type tcpIpForwardPayloadReply struct {
	Port uint32
}

type tcpIpForwardCancelPayload struct {
	Addr string
	Port uint32
}

// Function that can be used to implement calls to SetDeadline() after
// read/writes in copyTimeout()
type TimeoutFunc func()

// handleChannels
func handleChannels(client *sshClient, chans <-chan ssh.NewChannel) {
	for c := range chans {
		go handleChannel(client, c)
	}
}

// handleChannel
func handleChannel(client *sshClient, newChannel ssh.NewChannel) {

	debug(fmt.Sprintf("%s Channel type: %v", client.Name, newChannel.ChannelType()))

	if t := newChannel.ChannelType(); t == "direct-tcpip" {
		debug(fmt.Sprintf("%s Channel type accepted", client.Name))
		handleDirect(client, newChannel)
		return
	}
	debug(fmt.Sprintf("%s Channel type rejected (only direct-tcpip).", client.Name))
	newChannel.Reject(ssh.Prohibited, "Only \"direct-tcpip\" is accepted")
	return
}

// handleDirect
func handleDirect(client *sshClient, newChannel ssh.NewChannel) {
	var payload directTCPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		debug(fmt.Sprintf("%s Could not unmarshal extra data: %s", client.Name, err))
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad payload"))
		return
	}

	connection, requests, err := newChannel.Accept()
	if err != nil {
		debug(fmt.Sprintf("%s Could not accept channel (%s)", client.Name, err))
		return
	}
	go ssh.DiscardRequests(requests)

	// Create an object forward
	log1(fmt.Sprintf("%s Launching a new forwarder ...", client.Name))

	// Forward is a service that open a remote ssh connection to the given target
	// Target is get from the payload (ProxyCommand or ProxyJump parameters)
	sshForward := forwarder{}
	sshForward.InitialClientSshCon = client.SshConn
	sshForward.ConnID = client.Name
	sshForward.Principals = client.Principals
	sshForward.Gate = myGateway

	// set the remote destination (where to forward)
	sshForward.remoteDest = fmt.Sprintf("%s:%d", payload.Addr, payload.Port)

	// create a channel to receive the local port to use
	// we use listen("tcp",":0") to get the next available port
	sshForward.chanListenPort = make(chan int, 1)

	// launch a routine in background to handle forwarding
	go sshForward.Forward()

	// wait to receive the port where to forward original request
	localPortToForward := <-sshForward.chanListenPort

	// Connect to local forward service
	debug(fmt.Sprintf("%s Dialing to local forward: %d", client.Name, localPortToForward))
	rconn, err := net.Dial("tcp", "localhost:"+fmt.Sprintf("%d", localPortToForward))
	if err != nil {
		fail(fmt.Sprintf("%s Could not dial local port %d : %s", client.Name, localPortToForward, err))
		connection.Close()
		return
	}

	serve(connection, rconn, client, directtimeout)
}

func handleTcpIpForward(client *sshClient, req *ssh.Request) (net.Listener, *bindInfo, error) {
	var payload tcpIpForwardPayload

	//
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		fail(fmt.Sprintf("%s Unable to unmarshal payload", client.Name))
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Unable to parse payload")
	}

	debug(fmt.Sprintf("%s Request: %s %v %v", client.Name, req.Type, req.WantReply, payload))
	debug(fmt.Sprintf("%s Request to listen on %s:%d", client.Name, payload.Addr, payload.Port))

	//
	if payload.Addr != "localhost" && payload.Addr != "" {
		fail(fmt.Sprintf("%s Payload address is not \"localhost\" or empty: %s", client.Name, payload.Addr))
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Address is not permitted")
	}

	//
	bind := fmt.Sprintf("[%s]:%d", payload.Addr, payload.Port)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		fail(fmt.Sprintf("%s Listen failed for %s", client.Name, bind))
		req.Reply(false, []byte{})
		return nil, nil, err
	}

	// Tell client everything is OK
	reply := tcpIpForwardPayloadReply{payload.Port}
	req.Reply(true, ssh.Marshal(&reply))

	return ln, &bindInfo{bind, payload.Port, payload.Addr}, nil
}

func handleListener(client *sshClient, bindinfo *bindInfo, listener net.Listener) {
	// Start listening for connections
	for {
		lconn, err := listener.Accept()
		if err != nil {
			neterr := err.(net.Error)
			if neterr.Timeout() {
				fail(fmt.Sprintf("%s Accept failed with timeout: %s", client.Name, err))
				continue
			}
			if neterr.Temporary() {
				fail(fmt.Sprintf("%s Accept failed with temporary: %s", client.Name, err))
				continue
			}

			break
		}

		go handleForwardTcpIp(client, bindinfo, lconn)
	}
}

func handleForwardTcpIp(client *sshClient, bindinfo *bindInfo, lconn net.Conn) {
	remotetcpaddr := lconn.RemoteAddr().(*net.TCPAddr)
	raddr := remotetcpaddr.IP.String()
	rport := uint32(remotetcpaddr.Port)

	payload := forwardedTCPPayload{bindinfo.Addr, bindinfo.Port, raddr, uint32(rport)}
	mpayload := ssh.Marshal(&payload)

	// Open channel with client
	c, requests, err := client.SshConn.OpenChannel("forwarded-tcpip", mpayload)
	if err != nil {
		fail(fmt.Sprintf("%s Unable to get channel: %s. Hanging up requesting party!", client.Name, err))
		lconn.Close()
		return
	}
	if myGateway.Config.Verbose {
		log1(fmt.Sprintf("%s Channel opened for client", client.Name))
	}
	go ssh.DiscardRequests(requests)

	serve(c, lconn, client, forwardedtimeout)
}

func handleTcpIPForwardCancel(client *sshClient, req *ssh.Request) {
	if myGateway.Config.Verbose {
		log1(fmt.Sprintf("%s \"cancel-tcpip-forward\" called by client", client.Name))
	}
	var payload tcpIpForwardCancelPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		fail(fmt.Sprintf("%s Unable to unmarshal cancel payload", client.Name))
		req.Reply(false, []byte{})
	}

	bound := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)

	if listener, found := client.Listeners[bound]; found {
		listener.Close()
		delete(client.Listeners, bound)
		req.Reply(true, []byte{})
	}

	req.Reply(false, []byte{})
}

// handleRquest
func handleRequest(client *sshClient, reqs <-chan *ssh.Request) {
	for req := range reqs {
		client.Conn.SetDeadline(time.Now().Add(maintimeout))

		debug(fmt.Sprintf("%s Out of band request: %v %v", client.Name, req.Type, req.WantReply))

		// RFC4254: 7.1 for forwarding
		if req.Type == "tcpip-forward" {
			client.ListenMutex.Lock()
			/* If we are closing, do not set up a new listener */
			if client.Stopping {
				client.ListenMutex.Unlock()
				req.Reply(false, []byte{})
				continue
			}

			listener, bindinfo, err := handleTcpIpForward(client, req)
			if err != nil {
				client.ListenMutex.Unlock()
				continue
			}

			client.Listeners[bindinfo.Bound] = listener
			client.ListenMutex.Unlock()

			go handleListener(client, bindinfo, listener)
			continue
		} else if req.Type == "cancel-tcpip-forward" {
			client.ListenMutex.Lock()
			handleTcpIPForwardCancel(client, req)
			client.ListenMutex.Unlock()
			continue
		} else {
			// Discard everything else
			req.Reply(false, []byte{})
		}
	}
}

func serve(cssh ssh.Channel, conn net.Conn, client *sshClient, timeout time.Duration) {
	close := func() {
		cssh.Close()
		conn.Close()
		debug(fmt.Sprintf("%s Channel closed.", client.Name))
	}

	var once sync.Once
	go func() {
		//io.Copy(cssh, conn)
		bytes_written, err := copyTimeout(cssh, conn, func() {
			conn.SetDeadline(time.Now().Add(timeout))
			client.Conn.SetDeadline(time.Now().Add(maintimeout))
		})
		if err != nil {
			debug(fmt.Sprintf("%s copyTimeout failed with: %s", client.Name, err))
		}
		debug(fmt.Sprintf("%s Connection closed, bytes written: %d", client.Name, bytes_written))
		once.Do(close)
	}()
	go func() {
		//io.Copy(conn, cssh)
		bytes_written, err := copyTimeout(conn, cssh, func() {
			//debug(fmt.Sprintf("%s Updating deadline for direct|forwarded socket and main socket (received data)", client.Name))
			conn.SetDeadline(time.Now().Add(timeout))
			client.Conn.SetDeadline(time.Now().Add(maintimeout))
		})
		if err != nil {
			debug(fmt.Sprintf("%s copyTimeout failed with: %s", client.Name, err))
		}
		debug(fmt.Sprintf("%s Connection closed, bytes written: %d", client.Name, bytes_written))
		once.Do(close)
	}()
}

// Changed from pkg/io/io.go copyBuffer
func copyTimeout(dst io.Writer, src io.Reader, timeout TimeoutFunc) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			timeout()

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			timeout()
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}
