package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	color "github.com/logrusorgru/aurora"
)

const (
	configFile             = "./etc/config.toml"
	proxySshServerName     = "PROXY"
	forwarderSshServerName = "FORWARDER"
	remoteRealm            = "remote"
)

var (
	maintimeout      = time.Duration(10) * time.Minute
	directtimeout    = time.Duration(10) * time.Minute
	forwardedtimeout = time.Duration(10) * time.Minute
)

// main struct to share configuration
type gate struct {
	tomlConfig string

	// struct with running configuration
	Config Config
}

// TODO : fix
var myGateway = gate{}

func main() {

	log1("Starting ...")
	// read argument and load configuration
	myGateway.configGate()

	sshProxyConfig := &ssh.ServerConfig{
		//NoClientAuth: false,
		ServerVersion: "SSH-2.0-" + myGateway.Config.Proxy.ServerName,

		// TODO => config
		MaxAuthTries: 3,
	}

	// Setup Host Key
	sshProxyConfig.AddHostKey(loadHostKeys(myGateway.Config.Hostkey))

	// Setup SSH Banner
	sshProxyConfig.BannerCallback = func(conn ssh.ConnMetadata) string {
		return banner(myGateway.Config.Proxy.Banner)
	}

	sshProxyConfig.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {

		// TODO : LOG ?
		if err != nil {
			debug(fmt.Sprintf("Failed method \"%s\" for user %s from %s ssh2", method, conn.User(), conn.RemoteAddr()))
		} else {
			debug(fmt.Sprintf("Accepted method \"%s\" for user %s from %s ssh2", method, conn.User(), conn.RemoteAddr()))
		}
	}

	// Setup auth callbacks
	sshProxyConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

		connID := fmt.Sprintf("[%s/%v] %s", conn.User(), conn.RemoteAddr(), color.Sprintf(color.Red("|")))
		fingerprint := fmt.Sprintf("%v %v", key.Type(), ssh.FingerprintSHA256(key))
		debug(fmt.Sprintf("%s auth with \"%s\"", connID, fingerprint))

		// verify key type
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			debug(fmt.Sprintf("%s Unsupported key type.", connID))
			return nil, errors.New("Unsupported key type.")
		}

		// verify principals
		if len(cert.ValidPrincipals) == 0 {
			debug(fmt.Sprintf("%s No principal(s) found. Need at least 1.", connID))
			return nil, errors.New("No principal found. Need at least 1.")
		}
		debug(fmt.Sprintf("%s Principals: %s", connID, cert.ValidPrincipals))

		// verify keyID
		// key ID should contain the username
		if len(cert.KeyId) == 0 {
			debug(fmt.Sprintf("%s need a valid key ID for key.", connID))
			return nil, errors.New("No key ID found. Need one.")
		}
		authUser := strings.Split(cert.KeyId, "-")
		debug(fmt.Sprintf("%s Auth user: %s", connID, authUser[0]))
		// TODO : export real username
		connID = fmt.Sprintf("[%s/%s/%v] %s", conn.User(), authUser[0], conn.RemoteAddr(), color.Sprintf(color.Red("|")))

		// verify the signature of the cert
		CertChecker := ssh.CertChecker{}
		CertChecker.IsUserAuthority = func(key ssh.PublicKey) bool {
			publicKey, err := ioutil.ReadFile(myGateway.Config.CACert) // open private key
			if err != nil {
				fail(fmt.Sprintf("Failed to load private key from %s !\n", myGateway.Config.CACert))
				os.Exit(1)
			}

			serverCA, _, _, _, err := ssh.ParseAuthorizedKey(publicKey) // load CA
			if err != nil {
				fail(fmt.Sprintf("Failed to parse private key from %s : %s!\n", myGateway.Config.CACert, err))
				os.Exit(1)
			}

			keyCompare := bytes.Compare(serverCA.Marshal(), key.Marshal())
			if keyCompare == 0 {
				debug(fmt.Sprintf("%s Valid signature.", connID))
				return true
			} else {
				debug(fmt.Sprintf("%s Invalid signature.", connID))
				return false
			}
		}
		// Authenticate() will call IsUserAuthority() callback
		// also check if login user found in principal list
		permissions, err := CertChecker.Authenticate(conn, key)
		if err != nil {
			fail(fmt.Sprintf("%s Failed to Authenticate with cert: %s !\n", connID, err))
			os.Exit(1)
		}

		// CheckCert verify cert validity
		// looking for valid principal to connect to the proxy
		// also check certificate validity
		err = CertChecker.CheckCert(myGateway.Config.Proxy.AllowedPrincipal, cert)
		if err != nil {
			fail(fmt.Sprintf("%s Unable to found principal \"%s\": %s !\n", connID, myGateway.Config.Proxy.AllowedPrincipal, err))
			os.Exit(1)
		}
		debug(fmt.Sprintf("%s Principal \"%s\" found.", connID, myGateway.Config.Proxy.AllowedPrincipal))

		// FIX OR USE
		permissions.Extensions["connID"] = connID
		permissions.Extensions["principals"] = strings.Join(cert.ValidPrincipals, ",")
		permissions.CriticalOptions["source-address"] = ""

		return permissions, nil
	}

	// Setup SSH crypto
	if len(myGateway.Config.Proxy.Ciphers) > 0 {
		sshProxyConfig.Config.Ciphers = myGateway.Config.Proxy.Ciphers
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this ciphers: %s", sshProxyConfig.Config.Ciphers))
		}
	}
	if len(myGateway.Config.Proxy.Macs) > 0 {
		sshProxyConfig.Config.MACs = myGateway.Config.Proxy.Macs
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this macs: %s", sshProxyConfig.Config.MACs))
		}
	}
	if len(myGateway.Config.Proxy.KeyExchange) > 0 {
		sshProxyConfig.Config.KeyExchanges = myGateway.Config.Proxy.KeyExchange
		if myGateway.Config.Debug {
			debug(fmt.Sprintf("SSH will use this keyExchange: %s", sshProxyConfig.Config.KeyExchanges))
		}
	}

	// Bind to listenAddr ...
	listenAddr := fmt.Sprintf("[%s]:%d", myGateway.Config.Proxy.Interface, myGateway.Config.Proxy.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fail(fmt.Sprintf("Failed to listen on %s: %s", listenAddr, err))
		os.Exit(1)
	}

	// Wait for connections ...
	if myGateway.Config.Verbose {
		log1(fmt.Sprintf("Listening on %s", listenAddr))
	}

	for {
		newConn, err := listener.Accept()
		if err != nil {
			fail(fmt.Sprintf("Failed to accept incoming connection (%s)", err))
			continue
		}

		log1(fmt.Sprintf("Accept new TCP connection on %s from %s", listenAddr, newConn.RemoteAddr()))

		// TODO : fix ?
		newConn.SetDeadline(time.Now().Add(maintimeout))

		// We perform the ssh handshake in a goroutine so the handshake cannot
		// block incoming connections.
		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(newConn, sshProxyConfig)
			if err != nil {
				fail(fmt.Sprintf("Failed to handshake: %s (rip: %v)", err, newConn.RemoteAddr()))
				return
			}

			client := sshClient{
				sshConn.Permissions.Extensions["connID"],
				sshConn.Permissions.Extensions["principals"],
				newConn,
				sshConn,
				make(map[string]net.Listener),
				false,
				sync.Mutex{},
			}

			log1(fmt.Sprintf("%s SSH connection accepted.", client.Name))
			debug(fmt.Sprintf("%s Principals: %s", client.Name, client.Principals))

			// Start the clean-up function: will wait for the socket to be
			// closed (either by remote, protocol or deadline/timeout)
			// and close any listeners if any
			go func() {
				err := client.SshConn.Wait()
				client.ListenMutex.Lock()
				defer client.ListenMutex.Unlock()
				client.Stopping = true

				if myGateway.Config.Verbose {
					log1(fmt.Sprintf("%s SSH connection closed: %s", client.Name, err))
				}

				for bind, listener := range client.Listeners {
					if myGateway.Config.Verbose {
						log1(fmt.Sprintf("%s Closing listener bound to %s", client.Name, bind))
					}
					listener.Close()
				}
			}()

			// Accept requests & channels
			go handleRequest(&client, reqs)
			go handleChannels(&client, chans)
		}()
	}
}
