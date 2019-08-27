package main

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	AuthorisedKeys string `toml:authorized_keys`
	CACert         string
	Debug          bool
	Verbose        bool

	Hostkey   string
	Proxy     Proxy     `toml:"proxy"`
	Forwarder Forwarder `toml:"forwarder"`
	Log       Log       `toml:log`
}

type Proxy struct {
	Port              uint16
	Interface         net.IP
	Ciphers           []string `toml:ssh_macs`
	Macs              []string `toml:ssh_ciphers`
	KeyExchange       []string `toml:ssh_keyExchange`
	ServerName        string
	Banner            string
	AllowedPrincipal  string
	CustomerPrincipal string
}

type Forwarder struct {
	Hostkey             string
	Port                uint16
	Ciphers             []string `toml:ssh_macs`
	Macs                []string `toml:ssh_ciphers`
	KeyExchange         []string `toml:ssh_keyExchange`
	ServerName          string
	Banner              string
	RemoteUser          string
	RemoteUserPrincipal bool
}

type Log struct {
	LogDir string
	//	customerPrincipal string
	//	logHierarchy      string
}

func (c *Config) loadConfig(configFile string) {

	if _, err := toml.DecodeFile(configFile, &c); err != nil {
		fmt.Println("Fail to parse config file", "config.toml", ":")
		fmt.Println(err)
		os.Exit(1)
	}

	if c.Debug {
		debug(fmt.Sprintf("Successful load TOML config file !", configFile))
	}

	if c.Proxy.ServerName == "" {
		c.Proxy.ServerName = proxySshServerName
	}
	if c.Forwarder.ServerName == "" {
		c.Forwarder.ServerName = forwarderSshServerName
	}
}

func (c *Config) printConfig() {

	// TODO
	debug("--- Current configuration ---")
	debug(fmt.Sprintf("verbose = %t", c.Verbose))
	debug(fmt.Sprintf("debug = %t", c.Debug))
	debug(fmt.Sprintf("authorized_keys = %s", c.AuthorisedKeys))
	debug(fmt.Sprintf("hostKey = %s", c.Hostkey))
	debug(fmt.Sprintf("CACert = %s", c.CACert))
	debug("[proxy]")
	debug(fmt.Sprintf("port = %d", c.Proxy.Port))
	debug(fmt.Sprintf("interface = %s", c.Proxy.Interface))
	debug(fmt.Sprintf("sshCiphers = %q", c.Proxy.Ciphers))
	debug(fmt.Sprintf("sshMacs = %s", c.Proxy.Macs))
	debug(fmt.Sprintf("sshKeyExchange = %s", c.Proxy.KeyExchange))
	debug(fmt.Sprintf("sshServerName = %s", c.Proxy.ServerName))
	debug(fmt.Sprintf("banner = %s", c.Proxy.Banner))
	debug(fmt.Sprintf("allowedPrincipal = %s", c.Proxy.AllowedPrincipal))
	debug("[forwarder]")
	debug(fmt.Sprintf("port = %d", c.Proxy.Port))
	debug(fmt.Sprintf("sshCiphers = %s", c.Forwarder.Ciphers))
	debug(fmt.Sprintf("sshMacs = %s", c.Forwarder.Macs))
	debug(fmt.Sprintf("sshKeyExchange = %s", c.Forwarder.KeyExchange))
	debug(fmt.Sprintf("sshServerName = %s", c.Forwarder.ServerName))
	debug(fmt.Sprintf("banner = %s", c.Forwarder.Banner))
	debug("[log]")
	debug(fmt.Sprintf("logDir = %s", c.Log.LogDir))
	debug("--- END OF CURRENT CONFIGURATION ---")
}
