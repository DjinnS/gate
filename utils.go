package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	color "github.com/logrusorgru/aurora"
	flag "github.com/spf13/pflag"
)

// configGate parse input argument and load configuration file
func (g *gate) configGate() {
	var flags = flag.NewFlagSet("progName", flag.ExitOnError)

	// define custom Usage() function
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flags.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n")
		os.Exit(1)
	}

	// get TOML config file path
	flags.StringVarP(&g.tomlConfig, "config", "c", configFile, "Path to the config file")
	flags.SortFlags = false
	flags.SetNormalizeFunc(func(f *flag.FlagSet, name string) flag.NormalizedName { return flag.NormalizedName(name) })
	err := flags.Parse(os.Args[1:])
	if err != nil {
		fail("Fail to parse command line arguments !")
		log.Fatalf("Fail to parse command line arguments !")
		os.Exit(1)
	}

	// load config file
	g.Config.loadConfig(g.tomlConfig)
	if g.Config.Debug {
		g.Config.printConfig()
	}
}

// loadHostKeys load host key
func loadHostKeys(key string) ssh.Signer {
	privateBytes, err := ioutil.ReadFile(key)
	if err != nil {
		fail(fmt.Sprintf("Failed to load private key from %s !\n", key))
		os.Exit(1)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		fail(fmt.Sprintf("Failed to parse private key from %s !\n", key))
		os.Exit(1)
	}

	return private
}

// banner return the requested banner
func banner(b string) string {
	banner, err := ioutil.ReadFile(b)
	if err != nil {
		fail(fmt.Sprintf("Failed to load banner from %s !", b))
		return ""
	}
	return string(banner)
}

// debug print debug information
func debug(s string) {
	if myGateway.Config.Debug {
		log.Printf("%-9s %s\n", color.Sprintf(color.Cyan("[DEBUG]")), s)
	}
}

// log1 print level1 log information
func log1(s string) {
	if myGateway.Config.Verbose {
		log.Printf(fmt.Sprintf("%-9s %s\n", color.Sprintf(color.Green("[INFO]")), s))
	}
}

// fail print error in information
func fail(s string) {
	if myGateway.Config.Verbose {
		log.Printf("%-9s %s\n", color.Sprintf(color.Red("[ERROR]")), s)
	}
}
